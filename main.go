package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"

	"github.com/alecthomas/kingpin/v2"
)

//go:embed frontend/static
var staticFiles embed.FS

//go:embed templates
var templateFiles embed.FS

const (
	usernameRegexp         = `^([a-zA-Z0-9_.\-@])+$`
	passwordMinLength      = 6
	certsArchiveFileName   = "certs.tar.gz"
	ccdArchiveFileName     = "ccd.tar.gz"
	indexTxtDateLayout     = "060102150405Z"
	stringDateFormat       = "2006-01-02 15:04:05"
	downloadCertsApiUrl    = "api/data/certs/download"
	downloadCcdApiUrl      = "api/data/ccd/download"
	labelKeyIndexTxt       = "index.txt"
	labelKeyType           = "type"
	labelKeyName           = "name"
	labelKeyManagedBy      = "app.kubernetes.io/managed-by"
	labelValueClientAuth   = "clientAuth"
	labelValueManagedByApp = "ovpn-admin"

	kubeNamespaceFilePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

var (
	listenHost               = kingpin.Flag("listen.host", "host for ovpn-admin; empty means all interfaces (IPv4 and IPv6), e.g. 0.0.0.0, ::, ::1").Default("").Envar("OVPN_LISTEN_HOST").String()
	listenPort               = kingpin.Flag("listen.port", "port for ovpn-admin").Default("8080").Envar("OVPN_LISTEN_PORT").String()
	listenBaseUrl            = kingpin.Flag("listen.base-url", "base url for ovpn-admin").Default("/").Envar("OVPN_LISTEN_BASE_URL").String()
	serverRole               = kingpin.Flag("role", "server role, master or slave").Default("master").Envar("OVPN_ROLE").HintOptions("master", "slave").String()
	masterHost               = kingpin.Flag("master.host", "URL for the master server, IPv6 hosts in brackets: http://[fd00::1]:8080").Default("http://127.0.0.1").Envar("OVPN_MASTER_HOST").String()
	masterBasicAuthUser      = kingpin.Flag("master.basic-auth.user", "user for master server's Basic Auth").Default("").Envar("OVPN_MASTER_USER").String()
	masterBasicAuthPassword  = kingpin.Flag("master.basic-auth.password", "password for master server's Basic Auth").Default("").Envar("OVPN_MASTER_PASSWORD").String()
	masterSyncFrequency      = kingpin.Flag("master.sync-frequency", "master host data sync frequency in seconds").Default("600").Envar("OVPN_MASTER_SYNC_FREQUENCY").Int()
	masterSyncToken          = kingpin.Flag("master.sync-token", "master host data sync security token").Default("VerySecureToken").Envar("OVPN_MASTER_TOKEN").PlaceHolder("TOKEN").String()
	openvpnNetwork           = kingpin.Flag("ovpn.network", "IPv4 NETWORK/MASK_PREFIX (or NETWORK/NETMASK) for OpenVPN server").Default("172.16.100.0/24").Envar("OVPN_NETWORK").String()
	openvpnNetworkIPv6       = kingpin.Flag("ovpn.network.ipv6", "IPv6 NETWORK/PREFIX for OpenVPN server (server-ipv6), e.g. fd00:16:100::/64; empty disables IPv6").Default("").Envar("OVPN_NETWORK_IPV6").String()
	openvpnServer            = kingpin.Flag("ovpn.server", "HOST:PORT:PROTOCOL for OpenVPN server, IPv6 hosts in brackets: [2001:db8::1]:1194:udp; can have multiple values").Default("127.0.0.1:7777:tcp").Envar("OVPN_SERVER").PlaceHolder("HOST:PORT:PROTOCOL").Strings()
	openvpnServerBehindLB    = kingpin.Flag("ovpn.server.behindLB", "enable if your OpenVPN server is behind Kubernetes Service having the LoadBalancer type").Default("false").Envar("OVPN_LB").Bool()
	openvpnServiceName       = kingpin.Flag("ovpn.service", "the name of Kubernetes Service having the LoadBalancer type if your OpenVPN server is behind it").Default("openvpn-external").Envar("OVPN_LB_SERVICE").Strings()
	mgmtAddress              = kingpin.Flag("mgmt", "ALIAS=HOST:PORT for OpenVPN server mgmt interface, IPv6 hosts in brackets: main=[::1]:8989; can have multiple values").Default("main=127.0.0.1:8989").Envar("OVPN_MGMT").Strings()
	metricsPath              = kingpin.Flag("metrics.path", "URL path for exposing collected metrics").Default("/metrics").Envar("OVPN_METRICS_PATH").String()
	easyrsaDirPath           = kingpin.Flag("easyrsa.path", "path to easyrsa dir").Default("./easyrsa").Envar("EASYRSA_PATH").String()
	indexTxtPath             = kingpin.Flag("easyrsa.index-path", "path to easyrsa index file; empty means <easyrsa.path>/pki/index.txt").Default("").Envar("OVPN_INDEX_PATH").String()
	easyrsaBinPath           = kingpin.Flag("easyrsa.bin-path", "path to easyrsa script").Default("easyrsa").Envar("EASYRSA_BIN_PATH").String()
	ccdEnabled               = kingpin.Flag("ccd", "enable client-config-dir").Default("false").Envar("OVPN_CCD").Bool()
	ccdDir                   = kingpin.Flag("ccd.path", "path to client-config-dir").Default("./ccd").Envar("OVPN_CCD_PATH").String()
	clientConfigTemplatePath = kingpin.Flag("templates.clientconfig-path", "path to custom client.conf.tpl").Default("").Envar("OVPN_TEMPLATES_CC_PATH").String()
	ccdTemplatePath          = kingpin.Flag("templates.ccd-path", "path to custom ccd.tpl").Default("").Envar("OVPN_TEMPLATES_CCD_PATH").String()
	authByPassword           = kingpin.Flag("auth.password", "enable additional password authentication").Default("false").Envar("OVPN_AUTH").Bool()
	authDatabase             = kingpin.Flag("auth.db", "database path for password authentication").Default("./easyrsa/pki/users.db").Envar("OVPN_AUTH_DB_PATH").String()
	authDataBaseInit         = kingpin.Flag("auth.db-init", "enable database initialization if db user not exists or size is 0").Default("false").Envar("OVPN_AUTH_DB_INIT").Bool()
	logLevel                 = kingpin.Flag("log.level", "set log level: trace, debug, info, warn, error (default info)").Default("info").Envar("LOG_LEVEL").String()
	logFormat                = kingpin.Flag("log.format", "set log format: text, json (default text)").Default("text").Envar("LOG_FORMAT").String()
	storageBackend           = kingpin.Flag("storage.backend", "storage backend: filesystem, kubernetes.secrets (default filesystem)").Default("filesystem").Envar("STORAGE_BACKEND").String()
	clientCertExpirationDays = kingpin.Flag("client-cert.expiration-days", "Expiration period of OpenVPN client certificates in days, the period will shrink automatically to the CA expiration period").Default("3650").Envar("CLIENT_CERT_EXPIRATION_DAYS").String()

	certsArchivePath = "/tmp/" + certsArchiveFileName
	ccdArchivePath   = "/tmp/" + ccdArchiveFileName

	version = "2.0.0"
)

var logLevels = map[string]log.Level{
	"trace": log.TraceLevel,
	"debug": log.DebugLevel,
	"info":  log.InfoLevel,
	"warn":  log.WarnLevel,
	"error": log.ErrorLevel,
}

var logFormats = map[string]log.Formatter{
	"text": &log.TextFormatter{},
	"json": &log.JSONFormatter{},
}

var (
	ovpnServerCertExpire = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_server_cert_expire",
		Help: "openvpn server certificate expire time in days",
	},
	)

	ovpnServerCaCertExpire = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_server_ca_cert_expire",
		Help: "openvpn server CA certificate expire time in days",
	},
	)

	ovpnClientsTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_clients_total",
		Help: "total openvpn users",
	},
	)

	ovpnClientsRevoked = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_clients_revoked",
		Help: "revoked openvpn users",
	},
	)

	ovpnClientsExpired = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_clients_expired",
		Help: "expired openvpn users",
	},
	)

	ovpnClientsConnected = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_clients_connected",
		Help: "total connected openvpn clients",
	},
	)

	ovpnUniqClientsConnected = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "ovpn_uniq_clients_connected",
		Help: "uniq connected openvpn clients",
	},
	)

	ovpnClientCertificateExpire = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_cert_expire",
		Help: "openvpn user certificate expire time in days",
	},
		[]string{"client"},
	)

	ovpnClientConnectionInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_connection_info",
		Help: "openvpn user connection info. ip - assigned address from ovpn network. value - last time when connection was refreshed in unix format",
	},
		[]string{"client", "ip"},
	)

	ovpnClientConnectionFrom = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_connection_from",
		Help: "openvpn user connection info. ip - from which address connection was initialized. value - time when connection was initialized in unix format",
	},
		[]string{"client", "ip"},
	)

	ovpnClientBytesReceived = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_bytes_received",
		Help: "openvpn user bytes received",
	},
		[]string{"client"},
	)

	ovpnClientBytesSent = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "ovpn_client_bytes_sent",
		Help: "openvpn user bytes sent",
	},
		[]string{"client"},
	)
)

type OvpnAdmin struct {
	role                   string
	lastSyncTime           string
	lastSuccessfulSyncTime string
	masterHostBasicAuth    bool
	masterSyncToken        string
	clients                []OpenvpnClient
	activeClients          []clientStatus
	promRegistry           *prometheus.Registry
	mgmtInterfaces         map[string]string
	modules                []string
	createUserMutex        *sync.Mutex
}

type openvpnClientConfig struct {
	Hosts      []OpenvpnServer
	CA         string
	Cert       string
	Key        string
	TLS        string
	PasswdAuth bool
}

type OpenvpnClient struct {
	Identity         string `json:"Identity"`
	AccountStatus    string `json:"AccountStatus"`
	ExpirationDate   string `json:"ExpirationDate"`
	RevocationDate   string `json:"RevocationDate"`
	ConnectionStatus string `json:"ConnectionStatus"`
	Connections      int    `json:"Connections"`
}

type indexTxtLine struct {
	Flag              string
	ExpirationDate    string
	RevocationDate    string
	SerialNumber      string
	Filename          string
	DistinguishedName string
	Identity          string
}

func (oAdmin *OvpnAdmin) userListHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)

	if *storageBackend == "kubernetes.secrets" {
		err := app.updateIndexTxtOnDisk()
		if err != nil {
			log.Errorln(err)
		}
		oAdmin.clients = oAdmin.usersList()
	}

	usersList, _ := json.Marshal(oAdmin.clients)
	fmt.Fprintf(w, "%s", usersList)
}

func (oAdmin *OvpnAdmin) userStatisticHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	_ = r.ParseForm()
	userStatistic, _ := json.Marshal(oAdmin.getUserStatistic(r.FormValue("username")))
	fmt.Fprintf(w, "%s", userStatistic)
}

func (oAdmin *OvpnAdmin) userCreateHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	_ = r.ParseForm()
	userCreated, userCreateStatus := oAdmin.userCreate(r.FormValue("username"), r.FormValue("password"))

	if userCreated {
		oAdmin.clients = oAdmin.usersList()
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, userCreateStatus)
		return
	} else {
		http.Error(w, userCreateStatus, http.StatusUnprocessableEntity)
	}
}
func (oAdmin *OvpnAdmin) userRotateHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	_ = r.ParseForm()
	err, msg := oAdmin.userRotate(r.FormValue("username"), r.FormValue("password"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, msg)
	}
}

func (oAdmin *OvpnAdmin) userDeleteHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	_ = r.ParseForm()
	err, msg := oAdmin.userDelete(r.FormValue("username"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, msg)
	}
}

func (oAdmin *OvpnAdmin) userRevokeHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	_ = r.ParseForm()
	err, msg := oAdmin.userRevoke(r.FormValue("username"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, msg)
	}
}

func (oAdmin *OvpnAdmin) userUnrevokeHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	_ = r.ParseForm()
	err, msg := oAdmin.userUnrevoke(r.FormValue("username"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	} else {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, msg)
	}
}

func (oAdmin *OvpnAdmin) userChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	_ = r.ParseForm()
	if *authByPassword {
		err, msg := oAdmin.userChangePassword(r.FormValue("username"), r.FormValue("password"))
		status, code := "ok", http.StatusOK
		if err != nil {
			status, code = "error", http.StatusInternalServerError
		}
		body, _ := json.Marshal(map[string]string{"status": status, "message": msg})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_, _ = w.Write(body)
	} else {
		http.Error(w, `{"status":"error"}`, http.StatusNotImplemented)
	}

}

func (oAdmin *OvpnAdmin) userShowConfigHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	_ = r.ParseForm()
	fmt.Fprint(w, oAdmin.renderClientConfig(r.FormValue("username")))
}

func (oAdmin *OvpnAdmin) userDisconnectHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	_ = r.ParseForm()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	// 	fmt.Fprintf(w, "%s", userDisconnect(r.FormValue("username")))
	fmt.Fprintf(w, "%s", r.FormValue("username"))
}

func (oAdmin *OvpnAdmin) userShowCcdHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	_ = r.ParseForm()
	userCcd, err := oAdmin.getCcd(r.FormValue("username"))
	if err != nil {
		status := http.StatusBadRequest
		var notFound userNotFoundError
		if errors.As(err, &notFound) {
			status = http.StatusNotFound
		}
		http.Error(w, err.Error(), status)
		return
	}
	ccd, _ := json.Marshal(userCcd)
	fmt.Fprintf(w, "%s", ccd)
}

func (oAdmin *OvpnAdmin) userApplyCcdHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusLocked)
		return
	}
	var ccd Ccd
	if r.Body == nil {
		http.Error(w, "Please send a request body", http.StatusBadRequest)
		return
	}

	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&ccd)
	if err != nil {
		log.Errorln(err)
		http.Error(w, "invalid request body: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}

	ccdApplied, applyStatus := oAdmin.modifyCcd(ccd)

	if ccdApplied {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, applyStatus)
		return
	} else {
		http.Error(w, applyStatus, http.StatusUnprocessableEntity)
	}
}

func (oAdmin *OvpnAdmin) serverSettingsHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	enabledModules, enabledModulesErr := json.Marshal(oAdmin.modules)
	if enabledModulesErr != nil {
		log.Errorln(enabledModulesErr)
	}
	fmt.Fprintf(w, `{"status":"ok", "serverRole": "%s", "modules": %s }`, oAdmin.role, string(enabledModules))
}

func (oAdmin *OvpnAdmin) lastSyncTimeHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug(r.RemoteAddr, " ", r.RequestURI)
	fmt.Fprint(w, oAdmin.lastSyncTime)
}

func (oAdmin *OvpnAdmin) lastSuccessfulSyncTimeHandler(w http.ResponseWriter, r *http.Request) {
	log.Debug(r.RemoteAddr, " ", r.RequestURI)
	fmt.Fprint(w, oAdmin.lastSuccessfulSyncTime)
}

func (oAdmin *OvpnAdmin) downloadCertsHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusBadRequest)
		return
	}
	if *storageBackend == "kubernetes.secrets" {
		http.Error(w, `{"status":"error"}`, http.StatusBadRequest)
		return
	}
	_ = r.ParseForm()
	token := r.Form.Get("token")

	if token != oAdmin.masterSyncToken {
		http.Error(w, `{"status":"error"}`, http.StatusForbidden)
		return
	}

	archiveCerts()
	w.Header().Set("Content-Disposition", "attachment; filename="+certsArchiveFileName)
	http.ServeFile(w, r, certsArchivePath)
}

func (oAdmin *OvpnAdmin) downloadCcdHandler(w http.ResponseWriter, r *http.Request) {
	log.Info(r.RemoteAddr, " ", r.RequestURI)
	if oAdmin.role == "slave" {
		http.Error(w, `{"status":"error"}`, http.StatusBadRequest)
		return
	}
	if *storageBackend == "kubernetes.secrets" {
		http.Error(w, `{"status":"error"}`, http.StatusBadRequest)
		return
	}
	_ = r.ParseForm()
	token := r.Form.Get("token")

	if token != oAdmin.masterSyncToken {
		http.Error(w, `{"status":"error"}`, http.StatusForbidden)
		return
	}

	archiveCcd()
	w.Header().Set("Content-Disposition", "attachment; filename="+ccdArchiveFileName)
	http.ServeFile(w, r, ccdArchivePath)
}

var app OpenVPNPKI

func main() {
	kingpin.Version(version)
	kingpin.Parse()

	log.SetLevel(logLevels[*logLevel])
	log.SetFormatter(logFormats[*logFormat])

	if err := initNetworkConfig(); err != nil {
		log.Fatal(err)
	}

	if *storageBackend == "kubernetes.secrets" {
		err := app.run()
		if err != nil {
			log.Error(err)
		}
		if app.KubeClient == nil {
			log.Fatal("--storage.backend=kubernetes.secrets: kubernetes client is not initialized")
		}
	}

	if *indexTxtPath == "" {
		*indexTxtPath = *easyrsaDirPath + "/pki/index.txt"
	}

	if *authByPassword || *authDataBaseInit {
		ovpnUserPrepareDb()
	}

	ovpnAdmin := new(OvpnAdmin)

	ovpnAdmin.lastSyncTime = "unknown"
	ovpnAdmin.role = *serverRole
	ovpnAdmin.lastSuccessfulSyncTime = "unknown"
	ovpnAdmin.masterSyncToken = *masterSyncToken
	ovpnAdmin.promRegistry = prometheus.NewRegistry()
	ovpnAdmin.modules = []string{}
	ovpnAdmin.createUserMutex = &sync.Mutex{}
	ovpnAdmin.mgmtInterfaces = make(map[string]string)

	for _, mgmtInterface := range *mgmtAddress {
		parts := strings.SplitN(mgmtInterface, "=", 2)
		ovpnAdmin.mgmtInterfaces[parts[0]] = parts[len(parts)-1]
	}

	ovpnAdmin.mgmtCheckVersions()

	ovpnAdmin.registerMetrics()
	ovpnAdmin.setState()

	go ovpnAdmin.updateState()

	if *masterBasicAuthPassword != "" && *masterBasicAuthUser != "" {
		ovpnAdmin.masterHostBasicAuth = true
	} else {
		ovpnAdmin.masterHostBasicAuth = false
	}

	ovpnAdmin.modules = append(ovpnAdmin.modules, "core")

	if *authByPassword {
		if *storageBackend != "kubernetes.secrets" {
			ovpnAdmin.modules = append(ovpnAdmin.modules, "passwdAuth")
		} else {
			log.Fatal("Right now the keys `--storage.backend=kubernetes.secret` and `--auth.password` are not working together. Please use only one of them ")
		}
	}

	if *ccdEnabled {
		ovpnAdmin.modules = append(ovpnAdmin.modules, "ccd")
	}

	if ovpnNetworkV6.IsValid() {
		ovpnAdmin.modules = append(ovpnAdmin.modules, "ipv6")
	}

	if ovpnAdmin.role == "slave" {
		ovpnAdmin.syncDataFromMaster()
		go ovpnAdmin.syncWithMaster()
	}

	staticFS, _ := fs.Sub(staticFiles, "frontend/static")
	static := CacheControlWrapper(http.FileServer(http.FS(staticFS)), staticFS)

	http.Handle(*listenBaseUrl, http.StripPrefix(strings.TrimRight(*listenBaseUrl, "/"), static))
	http.HandleFunc(*listenBaseUrl+"api/server/settings", ovpnAdmin.serverSettingsHandler)
	http.HandleFunc(*listenBaseUrl+"api/users/list", ovpnAdmin.userListHandler)
	http.HandleFunc(*listenBaseUrl+"api/user/create", ovpnAdmin.userCreateHandler)
	http.HandleFunc(*listenBaseUrl+"api/user/change-password", ovpnAdmin.userChangePasswordHandler)
	http.HandleFunc(*listenBaseUrl+"api/user/rotate", ovpnAdmin.userRotateHandler)
	http.HandleFunc(*listenBaseUrl+"api/user/delete", ovpnAdmin.userDeleteHandler)
	http.HandleFunc(*listenBaseUrl+"api/user/revoke", ovpnAdmin.userRevokeHandler)
	http.HandleFunc(*listenBaseUrl+"api/user/unrevoke", ovpnAdmin.userUnrevokeHandler)
	http.HandleFunc(*listenBaseUrl+"api/user/config/show", ovpnAdmin.userShowConfigHandler)
	http.HandleFunc(*listenBaseUrl+"api/user/disconnect", ovpnAdmin.userDisconnectHandler)
	http.HandleFunc(*listenBaseUrl+"api/user/statistic", ovpnAdmin.userStatisticHandler)
	http.HandleFunc(*listenBaseUrl+"api/user/ccd", ovpnAdmin.userShowCcdHandler)
	http.HandleFunc(*listenBaseUrl+"api/user/ccd/apply", ovpnAdmin.userApplyCcdHandler)

	http.HandleFunc(*listenBaseUrl+"api/sync/last/try", ovpnAdmin.lastSyncTimeHandler)
	http.HandleFunc(*listenBaseUrl+"api/sync/last/successful", ovpnAdmin.lastSuccessfulSyncTimeHandler)
	http.HandleFunc(*listenBaseUrl+downloadCertsApiUrl, ovpnAdmin.downloadCertsHandler)
	http.HandleFunc(*listenBaseUrl+downloadCcdApiUrl, ovpnAdmin.downloadCcdHandler)

	http.Handle(*metricsPath, promhttp.HandlerFor(ovpnAdmin.promRegistry, promhttp.HandlerOpts{}))
	http.HandleFunc(*listenBaseUrl+"ping", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "pong")
	})

	log.Printf("Bind: %s", bindURL(*listenHost, *listenPort, *listenBaseUrl))
	log.Fatal(http.ListenAndServe(listenAddress(*listenHost, *listenPort), nil))
}

// CacheControlWrapper makes browsers revalidate the embedded web UI on every load:
// index.html holds the Vue template and must match dist/*.min.js, whose names are fixed,
// so a long max-age could combine a new index.html with an old bundle after an upgrade
// (or vice versa). The ETag (content hash) keeps revalidation cheap (304 Not Modified).
func CacheControlWrapper(h http.Handler, files fs.FS) http.Handler {
	etags := staticETags(files)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		if etag, ok := etags[staticFilePath(r.URL.Path)]; ok {
			w.Header().Set("ETag", etag)
		}
		h.ServeHTTP(w, r)
	})
}

// staticETags returns strong ETags (content hashes) of all files in files.
func staticETags(files fs.FS) map[string]string {
	etags := map[string]string{}
	err := fs.WalkDir(files, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(files, p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		etags[p] = `"` + hex.EncodeToString(sum[:16]) + `"`
		return nil
	})
	if err != nil {
		log.Warnf("computing ETags of static files: %v", err)
	}
	return etags
}

// staticFilePath maps a request path to the file http.FileServer serves for it ("/" -> "index.html").
func staticFilePath(urlPath string) string {
	p := strings.TrimPrefix(path.Clean("/"+urlPath), "/")
	if p == "" || strings.HasSuffix(urlPath, "/") {
		p = path.Join(p, "index.html")
	}
	return p
}

func (oAdmin *OvpnAdmin) registerMetrics() {
	oAdmin.promRegistry.MustRegister(ovpnServerCertExpire)
	oAdmin.promRegistry.MustRegister(ovpnServerCaCertExpire)
	oAdmin.promRegistry.MustRegister(ovpnClientsTotal)
	oAdmin.promRegistry.MustRegister(ovpnClientsRevoked)
	oAdmin.promRegistry.MustRegister(ovpnClientsConnected)
	oAdmin.promRegistry.MustRegister(ovpnUniqClientsConnected)
	oAdmin.promRegistry.MustRegister(ovpnClientsExpired)
	oAdmin.promRegistry.MustRegister(ovpnClientCertificateExpire)
	oAdmin.promRegistry.MustRegister(ovpnClientConnectionInfo)
	oAdmin.promRegistry.MustRegister(ovpnClientConnectionFrom)
	oAdmin.promRegistry.MustRegister(ovpnClientBytesReceived)
	oAdmin.promRegistry.MustRegister(ovpnClientBytesSent)
}

func (oAdmin *OvpnAdmin) setState() {
	oAdmin.activeClients = oAdmin.mgmtGetActiveClients()
	oAdmin.clients = oAdmin.usersList()

	ovpnServerCaCertExpire.Set(float64((getOvpnCaCertExpireDate().Unix() - time.Now().Unix()) / 3600 / 24))
}

func (oAdmin *OvpnAdmin) updateState() {
	for {
		time.Sleep(time.Duration(28) * time.Second)
		ovpnClientBytesSent.Reset()
		ovpnClientBytesReceived.Reset()
		ovpnClientConnectionFrom.Reset()
		ovpnClientConnectionInfo.Reset()
		ovpnClientCertificateExpire.Reset()
		go oAdmin.setState()
	}
}

func indexTxtParser(txt string) []indexTxtLine {
	var indexTxt []indexTxtLine

	txtLinesArray := strings.Split(txt, "\n")

	for _, v := range txtLinesArray {
		str := strings.Fields(v)
		if len(str) > 0 {
			switch {
			case (strings.HasPrefix(str[0], "E") || strings.HasPrefix(str[0], "V")) && len(str) >= 5:
				indexTxt = append(indexTxt, indexTxtLine{Flag: str[0], ExpirationDate: str[1], SerialNumber: str[2], Filename: str[3], DistinguishedName: str[4], Identity: str[4][strings.Index(str[4], "=")+1:]})
			case strings.HasPrefix(str[0], "R") && len(str) >= 6:
				indexTxt = append(indexTxt, indexTxtLine{Flag: str[0], ExpirationDate: str[1], RevocationDate: str[2], SerialNumber: str[3], Filename: str[4], DistinguishedName: str[5], Identity: str[5][strings.Index(str[5], "=")+1:]})
			}
		}
	}

	return indexTxt
}

func renderIndexTxt(data []indexTxtLine) string {
	indexTxt := ""
	for _, line := range data {
		switch {
		case line.Flag == "V", line.Flag == "E":
			indexTxt += fmt.Sprintf("%s\t%s\t\t%s\t%s\t%s\n", line.Flag, line.ExpirationDate, line.SerialNumber, line.Filename, line.DistinguishedName)
		case line.Flag == "R":
			indexTxt += fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\n", line.Flag, line.ExpirationDate, line.RevocationDate, line.SerialNumber, line.Filename, line.DistinguishedName)
		}
	}
	return indexTxt
}

func (oAdmin *OvpnAdmin) getClientConfigTemplate() *template.Template {
	if *clientConfigTemplatePath != "" {
		return template.Must(template.ParseFiles(*clientConfigTemplatePath))
	} else {
		clientConfigTplBytes, clientConfigTplErr := templateFiles.ReadFile("templates/client.conf.tpl")
		if clientConfigTplErr != nil {
			log.Errorf("clientConfigTpl not found in embedded templates: %v", clientConfigTplErr)
		}
		return template.Must(template.New("client-config").Parse(string(clientConfigTplBytes)))
	}
}

func (oAdmin *OvpnAdmin) renderClientConfig(username string) string {
	if usernameIsPathSafe(username) && checkUserExist(username) {
		hosts := slices.Clone(ovpnServers)

		if *openvpnServerBehindLB {
			var err error
			hosts, err = getOvpnServerHostsFromKubeApi()
			if err != nil {
				log.Error(err)
			}
		}

		log.Tracef("hosts for %s\n %v", username, hosts)

		conf := openvpnClientConfig{}
		conf.Hosts = hosts
		conf.CA = fRead(*easyrsaDirPath + "/pki/ca.crt")
		conf.TLS = fRead(*easyrsaDirPath + "/pki/ta.key")

		if *storageBackend == "kubernetes.secrets" {
			conf.Cert, conf.Key = app.easyrsaGetClientCert(username)
		} else {
			conf.Cert = fRead(*easyrsaDirPath + "/pki/issued/" + username + ".crt")
			conf.Key = fRead(*easyrsaDirPath + "/pki/private/" + username + ".key")
		}

		conf.PasswdAuth = *authByPassword

		t := oAdmin.getClientConfigTemplate()

		var tmp bytes.Buffer
		err := t.Execute(&tmp, conf)
		if err != nil {
			log.Errorf("something goes wrong during rendering config for %s", username)
			log.Debugf("rendering config for %s failed with error %v", username, err)
		}

		log.Tracef("Rendered config for user %s: %+v", username, tmp.String())

		return fmt.Sprintf("%+v", tmp.String())
	}
	log.Warnf("user \"%s\" not found", username)
	return fmt.Sprintf("user \"%s\" not found", username)
}

func validateUsername(username string) error {
	var validUsername = regexp.MustCompile(usernameRegexp)
	if validUsername.MatchString(username) && usernameIsPathSafe(username) {
		return nil
	} else {
		return errors.New(fmt.Sprintf("Username can only contains %s and must not be \".\" or \"..\"", usernameRegexp))
	}
}

// usernameIsPathSafe reports whether username can be used as a file name
// (no path separators, not "." or "..").
func usernameIsPathSafe(username string) bool {
	return username != "" && username != "." && username != ".." &&
		!strings.ContainsAny(username, "/\\\x00")
}

func validatePassword(password string) error {
	if utf8.RuneCountInString(password) < passwordMinLength {
		return errors.New(fmt.Sprintf("Password too short, password length must be greater or equal %d", passwordMinLength))
	} else {
		return nil
	}
}

// checkUserExist reports whether username is a user: a certificate with CN=username in index.txt
// that is not an OpenVPN server certificate (those are neither listed nor managed).
func checkUserExist(username string) bool {
	for _, u := range indexTxtParser(fRead(*indexTxtPath)) {
		if u.DistinguishedName == ("/CN="+username) && !isServerCertificate(u) {
			return true
		}
	}
	return false
}

// checkCommonNameExist reports whether index.txt has any certificate with CN=commonName,
// users and server certificates alike: a new user must not reuse it.
func checkCommonNameExist(commonName string) bool {
	for _, u := range indexTxtParser(fRead(*indexTxtPath)) {
		if u.DistinguishedName == ("/CN=" + commonName) {
			return true
		}
	}
	return false
}

func (oAdmin *OvpnAdmin) usersList() []OpenvpnClient {
	var users []OpenvpnClient

	totalCerts := 0
	validCerts := 0
	revokedCerts := 0
	expiredCerts := 0
	connectedUniqUsers := 0
	totalActiveConnections := 0
	apochNow := time.Now().Unix()

	for _, line := range indexTxtParser(fRead(*indexTxtPath)) {
		if isServerCertificate(line) {
			ovpnServerCertExpire.Set(float64((parseDateToUnix(indexTxtDateLayout, line.ExpirationDate) - apochNow) / 3600 / 24))
			continue
		}
		if !strings.Contains(line.Identity, "REVOKED") {
			totalCerts += 1
			ovpnClient := OpenvpnClient{Identity: line.Identity, ExpirationDate: parseDateToString(indexTxtDateLayout, line.ExpirationDate, stringDateFormat)}
			switch {
			case line.Flag == "V":
				ovpnClient.AccountStatus = "Active"
				validCerts += 1
			case line.Flag == "R":
				ovpnClient.AccountStatus = "Revoked"
				ovpnClient.RevocationDate = parseDateToString(indexTxtDateLayout, line.RevocationDate, stringDateFormat)
				revokedCerts += 1
			case line.Flag == "E":
				ovpnClient.AccountStatus = "Expired"
				expiredCerts += 1
			}

			ovpnClientCertificateExpire.WithLabelValues(line.Identity).Set(float64((parseDateToUnix(indexTxtDateLayout, line.ExpirationDate) - apochNow) / 3600 / 24))

			if (parseDateToUnix(indexTxtDateLayout, line.ExpirationDate) - apochNow) < 0 {
				if ovpnClient.AccountStatus != "Revoked" {
					ovpnClient.AccountStatus = "Expired"
				}
			}
			ovpnClient.Connections = 0

			userConnected, userConnectedTo := isUserConnected(line.Identity, oAdmin.activeClients)
			if userConnected {
				ovpnClient.ConnectionStatus = "Connected"
				for range userConnectedTo {
					ovpnClient.Connections += 1
					totalActiveConnections += 1
				}
				connectedUniqUsers += 1
			}

			users = append(users, ovpnClient)
		}
	}

	otherCerts := totalCerts - validCerts - revokedCerts - expiredCerts

	if otherCerts != 0 {
		log.Warnf("there are %d otherCerts", otherCerts)
	}

	ovpnClientsTotal.Set(float64(totalCerts))
	ovpnClientsRevoked.Set(float64(revokedCerts))
	ovpnClientsExpired.Set(float64(expiredCerts))
	ovpnClientsConnected.Set(float64(totalActiveConnections))
	ovpnUniqClientsConnected.Set(float64(connectedUniqUsers))

	return users
}

func (oAdmin *OvpnAdmin) userCreate(username, password string) (bool, string) {
	ucErr := fmt.Sprintf("User \"%s\" created", username)

	oAdmin.createUserMutex.Lock()
	defer oAdmin.createUserMutex.Unlock()

	if checkCommonNameExist(username) {
		ucErr = fmt.Sprintf("User \"%s\" already exists\n", username)
		log.Debugf("userCreate: checkCommonNameExist():  %s", ucErr)
		return false, ucErr
	}

	if err := validateUsername(username); err != nil {
		log.Debugf("userCreate: validateUsername(): %s", err.Error())
		return false, err.Error()
	}

	if *authByPassword {
		if err := validatePassword(password); err != nil {
			log.Debugf("userCreate: authByPassword(): %s", err.Error())
			return false, err.Error()
		}
	}

	// the password is stored before the certificate is issued: if it cannot be stored,
	// no certificate is left behind; if the certificate cannot be issued, the password is removed again
	if *authByPassword {
		// openvpn-user exits with 0 even when the INSERT fails (e.g. a database that was not migrated),
		// so the row is checked afterwards
		if _, err := runOpenvpnUser("create", "--user="+username, "--password="+password); err != nil || !ovpnUserExistsInDb(username) {
			log.Errorf("userCreate: saving the password of user %s failed: %v", username, err)
			return false, fmt.Sprintf("Failed to save the password of user \"%s\"", username)
		}
	}
	rollbackPassword := func() {
		if *authByPassword {
			if _, err := runOpenvpnUser("delete", "--force", "--user="+username); err != nil {
				log.Errorf("userCreate: removing the password of user %s: %v", username, err)
			}
		}
	}

	if *storageBackend == "kubernetes.secrets" {
		err := app.easyrsaBuildClient(username)
		if err != nil {
			log.Error(err)
			rollbackPassword()
			return false, err.Error()
		}
	} else {
		if _, err := runCommand(*easyrsaDirPath, "", *easyrsaBinPath, "--batch", "build-client-full", username, "nopass"); err != nil {
			log.Errorf("userCreate: %v", err)
			rollbackPassword()
			return false, fmt.Sprintf("Failed to issue certificate for user \"%s\"", username)
		}
	}

	log.Infof("Certificate for user %s issued", username)

	//oAdmin.clients = oAdmin.usersList()

	return true, ucErr
}

func (oAdmin *OvpnAdmin) userChangePassword(username, password string) (error, string) {

	if checkUserExist(username) {
		if err := validatePassword(password); err != nil {
			log.Warningf("userChangePassword: %s", err.Error())
			return err, err.Error()
		}

		// "change-password" of openvpn-user reports success also for a user without a row in the database
		if !ovpnUserExistsInDb(username) {
			if _, err := runOpenvpnUser("create", "--user="+username, "--password="+password); err != nil || !ovpnUserExistsInDb(username) {
				log.Errorf("userChangePassword: saving the password of user %s failed: %v", username, err)
				return fmt.Errorf("saving the password of user %q failed", username), "Failed to change password"
			}
		}

		if _, err := runOpenvpnUser("change-password", "--user="+username, "--password="+password); err != nil {
			log.Errorf("userChangePassword: %v", err)
			return err, "Failed to change password"
		}

		log.Infof("Password for user %s was changed", username)

		return nil, "Password changed"
	}

	return fmt.Errorf("user %q not found", username), fmt.Sprintf("User \"%s\" not found", username)
}

// runOpenvpnUser runs an openvpn-user command against --auth.db. Values are passed as
// --flag=value: kingpin (used by openvpn-user) does not accept a separate value that
// starts with "-", e.g. the password "-Secret1".
func runOpenvpnUser(command string, args ...string) (string, error) {
	return runCommand("", "", "openvpn-user", append([]string{command, "--db.path=" + *authDatabase}, args...)...)
}

// ovpnUserExistsInDb reports whether the openvpn-user database has a row for username, including
// revoked and deleted ones ("create" refuses those as well). "openvpn-user check" prints nothing
// since 1.0.5, so the table printed by "list --all" is parsed instead.
func ovpnUserExistsInDb(username string) bool {
	out, err := runOpenvpnUser("list", "--all")
	if err != nil {
		log.Errorf("ovpnUserExistsInDb: %v", err)
	}
	return ovpnUserListHasUser(out, username)
}

// ovpnUserListHasUser looks for username in the output of "openvpn-user list --all":
//
//	id | username | revoked | deleted | app_configured
//	1  | alice    | false   | false   | false
func ovpnUserListHasUser(out, username string) bool {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Split(line, "|")
		if len(fields) < 2 {
			continue
		}
		if _, err := strconv.ParseUint(strings.TrimSpace(fields[0]), 10, 64); err != nil {
			continue // header or an error message
		}
		if strings.TrimSpace(fields[1]) == username {
			return true
		}
	}
	return false
}

func (oAdmin *OvpnAdmin) getUserStatistic(username string) []clientStatus {
	var userStatistic []clientStatus
	for _, u := range oAdmin.activeClients {
		if u.CommonName == username {
			userStatistic = append(userStatistic, u)
		}
	}
	return userStatistic
}

func (oAdmin *OvpnAdmin) userRevoke(username string) (error, string) {
	log.Infof("Revoke certificate for user %s", username)
	if usernameIsPathSafe(username) && checkUserExist(username) {
		// check certificate valid flag 'V'
		if *storageBackend == "kubernetes.secrets" {
			err := app.easyrsaRevoke(username)
			if err != nil {
				log.Error(err)
			}
		} else {
			if _, err := runCommand(*easyrsaDirPath, "yes\n", *easyrsaBinPath, "revoke", username); err != nil {
				log.Errorf("userRevoke: %v", err)
				return fmt.Errorf("failed to revoke certificate for user %q", username), fmt.Sprintf("Failed to revoke certificate for user \"%s\"", username)
			}
			easyrsaGenCrl()
		}

		if *authByPassword {
			if _, err := runOpenvpnUser("revoke", "--user="+username); err != nil {
				log.Errorf("userRevoke: %v", err)
			}
		}

		crlFix()
		userConnected, userConnectedTo := isUserConnected(username, oAdmin.activeClients)
		log.Tracef("User %s connected: %t", username, userConnected)
		if userConnected {
			for _, connection := range userConnectedTo {
				oAdmin.mgmtKillUserConnection(username, connection)
				log.Infof("Session for user \"%s\" killed", username)
			}
		}

		oAdmin.setState()
		return nil, fmt.Sprintf("user \"%s\" revoked", username)
	}
	log.Infof("user \"%s\" not found", username)
	return errors.New(fmt.Sprintf("User \"%s\" not found", username)), fmt.Sprintf("User \"%s\" not found", username)
}

func (oAdmin *OvpnAdmin) userUnrevoke(username string) (error, string) {
	if usernameIsPathSafe(username) && checkUserExist(username) {
		if *storageBackend == "kubernetes.secrets" {
			err := app.easyrsaUnrevoke(username)
			if err != nil {
				log.Error(err)
			}
		} else {
			// check certificate revoked flag 'R'
			usersFromIndexTxt := indexTxtParser(fRead(*indexTxtPath))
			for i := range usersFromIndexTxt {
				if usersFromIndexTxt[i].DistinguishedName == "/CN="+username {
					if usersFromIndexTxt[i].Flag == "R" {

						usersFromIndexTxt[i].Flag = "V"
						usersFromIndexTxt[i].RevocationDate = ""

						err := fMove(fmt.Sprintf("%s/pki/revoked/certs_by_serial/%s.crt", *easyrsaDirPath, usersFromIndexTxt[i].SerialNumber), fmt.Sprintf("%s/pki/issued/%s.crt", *easyrsaDirPath, username))
						if err != nil {
							log.Error(err)
						}
						err = fMove(fmt.Sprintf("%s/pki/revoked/certs_by_serial/%s.crt", *easyrsaDirPath, usersFromIndexTxt[i].SerialNumber), fmt.Sprintf("%s/pki/certs_by_serial/%s.pem", *easyrsaDirPath, usersFromIndexTxt[i].SerialNumber))
						if err != nil {
							log.Error(err)
						}
						err = fMove(fmt.Sprintf("%s/pki/revoked/private_by_serial/%s.key", *easyrsaDirPath, usersFromIndexTxt[i].SerialNumber), fmt.Sprintf("%s/pki/private/%s.key", *easyrsaDirPath, username))
						if err != nil {
							log.Error(err)
						}
						err = fMove(fmt.Sprintf("%s/pki/revoked/reqs_by_serial/%s.req", *easyrsaDirPath, usersFromIndexTxt[i].SerialNumber), fmt.Sprintf("%s/pki/reqs/%s.req", *easyrsaDirPath, username))
						if err != nil {
							log.Error(err)
						}
						err = fWrite(*indexTxtPath, renderIndexTxt(usersFromIndexTxt))
						if err != nil {
							log.Error(err)
						}

						easyrsaGenCrl()

						if *authByPassword {
							if _, err := runOpenvpnUser("restore", "--user="+username); err != nil {
								log.Errorf("userUnrevoke: %v", err)
							}
						}

						crlFix()

						break
					}
				}
			}
			err := fWrite(*indexTxtPath, renderIndexTxt(usersFromIndexTxt))
			if err != nil {
				log.Error(err)
			}
			//fmt.Print(renderIndexTxt(usersFromIndexTxt))
		}
		crlFix()
		oAdmin.clients = oAdmin.usersList()
		return nil, fmt.Sprintf("{\"msg\":\"User %s successfully unrevoked\"}", username)
	}
	return errors.New(fmt.Sprintf("user \"%s\" not found", username)), fmt.Sprintf("{\"msg\":\"User \"%s\" not found\"}", username)
}

func (oAdmin *OvpnAdmin) userRotate(username, newPassword string) (error, string) {
	if usernameIsPathSafe(username) && checkUserExist(username) {
		if *storageBackend == "kubernetes.secrets" {
			err := app.easyrsaRotate(username, newPassword)
			if err != nil {
				log.Error(err)
			}
		} else {

			var oldUserIndex, newUserIndex int
			var oldUserSerial string

			uniqHash := strings.Replace(uuid.New().String(), "-", "", -1)

			usersFromIndexTxt := indexTxtParser(fRead(*indexTxtPath))
			for i := range usersFromIndexTxt {
				if usersFromIndexTxt[i].DistinguishedName == "/CN="+username {
					oldUserSerial = usersFromIndexTxt[i].SerialNumber
					usersFromIndexTxt[i].DistinguishedName = "/CN=REVOKED-" + username + "-" + uniqHash
					oldUserIndex = i
					break
				}
			}
			err := fWrite(*indexTxtPath, renderIndexTxt(usersFromIndexTxt))
			if err != nil {
				log.Error(err)
			}

			if *authByPassword {
				if _, err := runOpenvpnUser("delete", "--force", "--user="+username); err != nil {
					log.Errorf("userRotate: %v", err)
				}
			}

			userCreated, userCreateMessage := oAdmin.userCreate(username, newPassword)
			if !userCreated {
				usersFromIndexTxt = indexTxtParser(fRead(*indexTxtPath))
				for i := range usersFromIndexTxt {
					if usersFromIndexTxt[i].SerialNumber == oldUserSerial {
						usersFromIndexTxt[i].DistinguishedName = "/CN=" + username
						break
					}
				}
				err = fWrite(*indexTxtPath, renderIndexTxt(usersFromIndexTxt))
				if err != nil {
					log.Error(err)
				}
				return errors.New(fmt.Sprintf("error rotaing user due:  %s", userCreateMessage)), userCreateMessage
			}

			usersFromIndexTxt = indexTxtParser(fRead(*indexTxtPath))
			for i := range usersFromIndexTxt {
				if usersFromIndexTxt[i].DistinguishedName == "/CN="+username {
					newUserIndex = i
				}
				if usersFromIndexTxt[i].SerialNumber == oldUserSerial {
					oldUserIndex = i
				}
			}
			usersFromIndexTxt[oldUserIndex], usersFromIndexTxt[newUserIndex] = usersFromIndexTxt[newUserIndex], usersFromIndexTxt[oldUserIndex]

			err = fWrite(*indexTxtPath, renderIndexTxt(usersFromIndexTxt))
			if err != nil {
				log.Error(err)
			}

			easyrsaGenCrl()
		}
		crlFix()
		oAdmin.clients = oAdmin.usersList()
		return nil, fmt.Sprintf("{\"msg\":\"User %s successfully rotated\"}", username)
	}
	return errors.New(fmt.Sprintf("user \"%s\" not found", username)), fmt.Sprintf("{\"msg\":\"User \"%s\" not found\"}", username)
}

func (oAdmin *OvpnAdmin) userDelete(username string) (error, string) {
	if usernameIsPathSafe(username) && checkUserExist(username) {
		if *storageBackend == "kubernetes.secrets" {
			err := app.easyrsaDelete(username)
			if err != nil {
				log.Error(err)
			}
		} else {
			uniqHash := strings.Replace(uuid.New().String(), "-", "", -1)
			usersFromIndexTxt := indexTxtParser(fRead(*indexTxtPath))
			for i := range usersFromIndexTxt {
				if usersFromIndexTxt[i].DistinguishedName == "/CN="+username {
					usersFromIndexTxt[i].DistinguishedName = "/CN=REVOKED-" + username + "-" + uniqHash
					break
				}
			}
			if *authByPassword {
				if _, err := runOpenvpnUser("delete", "--force", "--user="+username); err != nil {
					log.Errorf("userDelete: %v", err)
				}
			}
			err := fWrite(*indexTxtPath, renderIndexTxt(usersFromIndexTxt))
			if err != nil {
				log.Error(err)
			}
			easyrsaGenCrl()
		}
		crlFix()
		oAdmin.clients = oAdmin.usersList()
		return nil, fmt.Sprintf("{\"msg\":\"User %s successfully deleted\"}", username)
	}
	return errors.New(fmt.Sprintf("User \"%s\" not found", username)), fmt.Sprintf("{\"msg\":\"User \"%s\" not found\"}", username)
}

func (oAdmin *OvpnAdmin) downloadCerts() bool {
	if fExist(certsArchivePath) {
		err := fDelete(certsArchivePath)
		if err != nil {
			log.Error(err)
		}
	}

	err := fDownload(certsArchivePath, *masterHost+*listenBaseUrl+downloadCertsApiUrl+"?token="+oAdmin.masterSyncToken, oAdmin.masterHostBasicAuth)
	if err != nil {
		log.Error(err)
		return false
	}

	return true
}

func (oAdmin *OvpnAdmin) downloadCcd() bool {
	if fExist(ccdArchivePath) {
		err := fDelete(ccdArchivePath)
		if err != nil {
			log.Error(err)
		}
	}

	err := fDownload(ccdArchivePath, *masterHost+*listenBaseUrl+downloadCcdApiUrl+"?token="+oAdmin.masterSyncToken, oAdmin.masterHostBasicAuth)
	if err != nil {
		log.Error(err)
		return false
	}

	return true
}

func archiveCerts() {
	err := createArchiveFromDir(*easyrsaDirPath+"/pki", certsArchivePath)
	if err != nil {
		log.Warnf("archiveCerts(): %s", err)
	}
}

func archiveCcd() {
	err := createArchiveFromDir(*ccdDir, ccdArchivePath)
	if err != nil {
		log.Warnf("archiveCcd(): %s", err)
	}
}

func unArchiveCerts() {
	if err := os.MkdirAll(*easyrsaDirPath+"/pki", 0755); err != nil {
		log.Warnf("unArchiveCerts(): error creating pki dir: %s", err)
	}

	err := extractFromArchive(certsArchivePath, *easyrsaDirPath+"/pki")
	if err != nil {
		log.Warnf("unArchiveCerts: extractFromArchive() %s", err)
	}
}

func unArchiveCcd() {
	if err := os.MkdirAll(*ccdDir, 0755); err != nil {
		log.Warnf("unArchiveCcd(): error creating ccd dir: %s", err)
	}

	err := extractFromArchive(ccdArchivePath, *ccdDir)
	if err != nil {
		log.Warnf("unArchiveCcd: extractFromArchive() %s", err)
	}
}

// ovpnUserPrepareDb creates the openvpn-user database when it is missing or empty and --auth.db-init
// is set, and brings an existing one to the schema of openvpn-user 1.0.9:
//   - db-init runs also for an existing database: it only adds missing tables, and the "migrations"
//     table it creates is required by db-migrate (without it db-migrate silently does nothing);
//   - db-migrate adds the column "secret" without a default, so users created by openvpn-user <= 1.0.4
//     get NULL there and "openvpn-user auth" fails for them; NULL is replaced by an empty string,
//     the value openvpn-user 1.0.9 stores for new users.
func ovpnUserPrepareDb() {
	fi, err := os.Stat(*authDatabase)
	if (errors.Is(err, os.ErrNotExist) || (err == nil && fi.Size() == 0)) && !*authDataBaseInit {
		log.Warnf("password database %s does not exist, use --auth.db-init to create it", *authDatabase)
		return
	}

	for _, command := range []string{"db-init", "db-migrate"} {
		if _, err := runOpenvpnUser(command); err != nil {
			log.Errorf("ovpnUserPrepareDb: %v", err)
			return
		}
	}

	fixNullSecrets := "UPDATE users SET secret = '' WHERE secret IS NULL;"
	if _, err := exec.LookPath("sqlite3"); err != nil {
		log.Warnf("sqlite3 not found: users created by openvpn-user <= 1.0.4 cannot log in until you run: sqlite3 %s \"%s\"", *authDatabase, fixNullSecrets)
		return
	}
	if _, err := runCommand("", "", "sqlite3", *authDatabase, fixNullSecrets); err != nil {
		log.Errorf("ovpnUserPrepareDb: %v", err)
	}
}

// easyrsaGenCrl regenerates the CRL with easyrsa (filesystem backend)
func easyrsaGenCrl() {
	if _, err := runCommand(*easyrsaDirPath, "", *easyrsaBinPath, "gen-crl"); err != nil {
		log.Errorf("easyrsa gen-crl: %v", err)
	}
}

func (oAdmin *OvpnAdmin) syncDataFromMaster() {
	retryCountMax := 3
	certsDownloadFailed := true
	ccdDownloadFailed := true

	for certsDownloadRetries := 0; certsDownloadRetries < retryCountMax; certsDownloadRetries++ {
		log.Infof("Downloading archive with certificates from master. Attempt %d", certsDownloadRetries)
		if oAdmin.downloadCerts() {
			certsDownloadFailed = false
			log.Info("Decompressing archive with certificates from master")
			unArchiveCerts()
			log.Info("Decompression archive with certificates from master completed")
			break
		} else {
			log.Warnf("Something goes wrong during downloading archive with certificates from master. Attempt %d", certsDownloadRetries)
		}
	}

	for ccdDownloadRetries := 0; ccdDownloadRetries < retryCountMax; ccdDownloadRetries++ {
		log.Infof("Downloading archive with ccd from master. Attempt %d", ccdDownloadRetries)
		if oAdmin.downloadCcd() {
			ccdDownloadFailed = false
			log.Info("Decompressing archive with ccd from master")
			unArchiveCcd()
			log.Info("Decompression archive with ccd from master completed")
			break
		} else {
			log.Warnf("Something goes wrong during downloading archive with ccd from master. Attempt %d", ccdDownloadRetries)
		}
	}

	oAdmin.lastSyncTime = time.Now().Format(stringDateFormat)
	if !ccdDownloadFailed && !certsDownloadFailed {
		oAdmin.lastSuccessfulSyncTime = time.Now().Format(stringDateFormat)
	}
}

func (oAdmin *OvpnAdmin) syncWithMaster() {
	for {
		time.Sleep(time.Duration(*masterSyncFrequency) * time.Second)
		oAdmin.syncDataFromMaster()
	}
}

func getOvpnServerHostsFromKubeApi() ([]OpenvpnServer, error) {
	notFound := []OpenvpnServer{{Host: "kubernetes services not found"}}

	config, err := rest.InClusterConfig()
	if err != nil {
		return notFound, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return notFound, err
	}

	serviceNamespace := strings.TrimSpace(fRead(kubeNamespaceFilePath))

	var hosts []OpenvpnServer
	seen := map[OpenvpnServer]bool{}
	var lastErr error

	for _, serviceName := range *openvpnServiceName {
		service, err := clientset.CoreV1().Services(serviceNamespace).Get(context.TODO(), serviceName, metav1.GetOptions{})
		if err != nil {
			log.Errorf("get kubernetes service %s: %v", serviceName, err)
			lastErr = err
			continue
		}

		log.Tracef("service from kube api %v", service)
		log.Tracef("service.Status.LoadBalancer from kube api %v", service.Status.LoadBalancer)

		if len(service.Spec.Ports) == 0 {
			log.Warnf("kubernetes service %s has no ports", serviceName)
			continue
		}
		port := strconv.Itoa(int(service.Spec.Ports[0].Port))
		protocol := strings.ToLower(string(service.Spec.Ports[0].Protocol))

		for _, ingress := range service.Status.LoadBalancer.Ingress {
			lbHost := ingress.IP
			if lbHost == "" {
				lbHost = ingress.Hostname
			}
			if lbHost == "" {
				continue
			}

			host := OpenvpnServer{Host: lbHost, Port: port, Protocol: protocol}
			if seen[host] {
				continue
			}
			seen[host] = true
			hosts = append(hosts, host)
		}
	}

	if len(hosts) == 0 {
		return notFound, lastErr
	}

	return hosts, nil
}

func getOvpnCaCertExpireDate() time.Time {
	caCertPath := *easyrsaDirPath + "/pki/ca.crt"
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		log.Errorf("error read file %s: %s", caCertPath, err.Error())
	}

	certPem, _ := pem.Decode(caCert)
	if certPem == nil {
		log.Errorf("error decode certificate %s", caCertPath)
		return time.Now()
	}
	certPemBytes := certPem.Bytes

	cert, err := x509.ParseCertificate(certPemBytes)
	if err != nil {
		log.Errorf("error parse certificate ca.crt: %s", err.Error())
		return time.Now()
	}

	return cert.NotAfter
}

// https://community.openvpn.net/openvpn/ticket/623
func crlFix() {
	err := os.Chmod(*easyrsaDirPath+"/pki", 0755)
	if err != nil {
		log.Error(err)
	}
	err = os.Chmod(*easyrsaDirPath+"/pki/crl.pem", 0644)
	if err != nil {
		log.Error(err)
	}
}
