package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	secretCA         = "openvpn-pki-ca"
	secretServer     = "openvpn-pki-server"
	secretClientTmpl = "openvpn-pki-%d"
	secretCRL        = "openvpn-pki-crl"
	secretIndexTxt   = "openvpn-pki-index-txt"
	secretDHandTA    = "openvpn-pki-dh-and-ta"
	certFileName     = "tls.crt"
	privKeyFileName  = "tls.key"
)

// <year><month><day><hour><minute><second>Z
const indexTxtDateFormat = "060102150405Z"

var namespace = "default"

type OpenVPNPKI struct {
	CAPrivKeyRSA     *rsa.PrivateKey
	CAPrivKeyPEM     *bytes.Buffer
	CACert           *x509.Certificate
	CACertPEM        *bytes.Buffer
	ServerPrivKeyRSA *rsa.PrivateKey
	ServerPrivKeyPEM *bytes.Buffer
	ServerCert       *x509.Certificate
	ServerCertPEM    *bytes.Buffer
	ClientCerts      []ClientCert
	RevokedCerts     []RevokedCert
	KubeClient       *kubernetes.Clientset
}

type ClientCert struct {
	PrivKeyRSA *rsa.PrivateKey
	PrivKeyPEM *bytes.Buffer
	Cert       *x509.Certificate
	CertPEM    *bytes.Buffer
}

type RevokedCert struct {
	RevokedTime time.Time         `json:"revokedTime"`
	CommonName  string            `json:"commonName"`
	Cert        *x509.Certificate `json:"cert"`
}

func (openVPNPKI *OpenVPNPKI) run() (err error) {
	if _, err := os.Stat(kubeNamespaceFilePath); err == nil {
		file, err := ioutil.ReadFile(kubeNamespaceFilePath)
		if err != nil {
			return err
		}
		namespace = string(file)
	}

	err = openVPNPKI.initKubeClient()
	if err != nil {
		return
	}

	err = openVPNPKI.initPKI()
	if err != nil {
		return
	}

	err = openVPNPKI.indexTxtUpdate()
	if err != nil {
		log.Error(err)
	}

	err = openVPNPKI.easyrsaGenCRL()
	if err != nil {
		log.Error(err)
	}

	if res, _ := openVPNPKI.secretCheckExists(secretDHandTA); !res {
		err := openVPNPKI.secretGenTaKeyAndDHParam()
		if err != nil {
			log.Error(err)
		}
	}

	err = openVPNPKI.updateFilesFromSecrets()
	if err != nil {
		log.Error(err)
	}

	err = openVPNPKI.updateCRLOnDisk()
	if err != nil {
		log.Error(err)
	}

	err = openVPNPKI.updateIndexTxtOnDisk()
	if err != nil {
		log.Error(err)
	}

	err = openVPNPKI.updateCcdOnDisk()
	if err != nil {
		log.Error(err)
	}

	return
}

func (openVPNPKI *OpenVPNPKI) initKubeClient() (err error) {
	config, _ := rest.InClusterConfig()
	openVPNPKI.KubeClient, err = kubernetes.NewForConfig(config)
	return
}

func (openVPNPKI *OpenVPNPKI) initPKI() (err error) {
	if res, _ := openVPNPKI.secretCheckExists(secretCA); res {
		cert, err := openVPNPKI.secretGetClientCert(secretCA)
		if err != nil {
			return err
		}

		openVPNPKI.CAPrivKeyPEM = cert.PrivKeyPEM
		openVPNPKI.CAPrivKeyRSA = cert.PrivKeyRSA
		openVPNPKI.CACertPEM = cert.CertPEM
		openVPNPKI.CACert = cert.Cert
	} else {
		openVPNPKI.CAPrivKeyPEM, err = genPrivKey()
		if err != nil {
			return
		}
		openVPNPKI.CAPrivKeyRSA, err = decodePrivKey(openVPNPKI.CAPrivKeyPEM.Bytes())

		openVPNPKI.CACertPEM, _ = genCA(openVPNPKI.CAPrivKeyRSA)
		openVPNPKI.CACert, err = decodeCert(openVPNPKI.CACertPEM.Bytes())
		if err != nil {
			return
		}

		secretMetaData := metav1.ObjectMeta{Name: secretCA}

		secretData := map[string][]byte{
			certFileName:    openVPNPKI.CACertPEM.Bytes(),
			privKeyFileName: openVPNPKI.CAPrivKeyPEM.Bytes(),
		}

		err = openVPNPKI.secretCreate(secretMetaData, secretData, v1.SecretTypeTLS)
		if err != nil {
			return
		}
	}

	if res, _ := openVPNPKI.secretCheckExists(secretServer); res {
		cert, err := openVPNPKI.secretGetClientCert(secretServer)
		if err != nil {
			return err
		}

		openVPNPKI.ServerPrivKeyPEM = cert.PrivKeyPEM
		openVPNPKI.ServerPrivKeyRSA = cert.PrivKeyRSA
		openVPNPKI.ServerCertPEM = cert.CertPEM
		openVPNPKI.ServerCert = cert.Cert
	} else {
		openVPNPKI.ServerPrivKeyPEM, err = genPrivKey()
		if err != nil {
			return
		}

		openVPNPKI.ServerPrivKeyRSA, err = decodePrivKey(openVPNPKI.ServerPrivKeyPEM.Bytes())
		if err != nil {
			return
		}

		openVPNPKI.ServerCertPEM, _ = genServerCert(openVPNPKI.ServerPrivKeyRSA, openVPNPKI.CAPrivKeyRSA, openVPNPKI.CACert, "server")
		openVPNPKI.ServerCert, err = decodeCert(openVPNPKI.ServerCertPEM.Bytes())

		secretMetaData := metav1.ObjectMeta{
			Name: secretServer,
			Labels: map[string]string{
				"index.txt": "",
				"name":      "server",
				"type":      "serverAuth",
			},
		}

		secretData := map[string][]byte{
			certFileName:    openVPNPKI.ServerCertPEM.Bytes(),
			privKeyFileName: openVPNPKI.ServerPrivKeyPEM.Bytes(),
		}

		err = openVPNPKI.secretCreate(secretMetaData, secretData, v1.SecretTypeTLS)
		if err != nil {
			return
		}
	}

	return
}

func (openVPNPKI *OpenVPNPKI) indexTxtUpdate() (err error) {
	secrets, err := openVPNPKI.secretsGetByLabels("index.txt=")
	if err != nil {
		return
	}

	var indexTxt string
	for _, secret := range secrets.Items {
		certPEM := bytes.NewBuffer(secret.Data[certFileName])
		log.Trace("indexTxtUpdate:" + secret.Name)
		cert, err := decodeCert(certPEM.Bytes())
		if err != nil {
			return nil
		}

		log.Trace(cert.Subject.CommonName)

		if secret.Annotations["revokedAt"] == "" {
			indexTxt += fmt.Sprintf("%s\t%s\t\t%s\t%s\t%s\n", "V", cert.NotAfter.Format(indexTxtDateFormat), fmt.Sprintf("%d", cert.SerialNumber), "unknown", "/CN="+secret.Labels["name"])
		} else if cert.NotAfter.Before(time.Now()) {
			indexTxt += fmt.Sprintf("%s\t%s\t\t%s\t%s\t%s\n", "E", cert.NotAfter.Format(indexTxtDateFormat), fmt.Sprintf("%d", cert.SerialNumber), "unknown", "/CN="+secret.Labels["name"])
		} else {
			indexTxt += fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\n", "R", cert.NotAfter.Format(indexTxtDateFormat), secret.Annotations["revokedAt"], fmt.Sprintf("%d", cert.SerialNumber), "unknown", "/CN="+secret.Labels["name"])
		}

	}

	secretMetaData := metav1.ObjectMeta{Name: secretIndexTxt}

	secretData := map[string][]byte{"index.txt": []byte(indexTxt)}

	if res, _ := openVPNPKI.secretCheckExists(secretIndexTxt); !res {
		err = openVPNPKI.secretCreate(secretMetaData, secretData, v1.SecretTypeOpaque)
	} else {
		err = openVPNPKI.secretUpdate(secretMetaData, secretData, v1.SecretTypeOpaque)
	}

	return
}

func (openVPNPKI *OpenVPNPKI) updateIndexTxtOnDisk() (err error) {
	secret, err := openVPNPKI.secretGetByName(secretIndexTxt)
	indexTxt := secret.Data["index.txt"]
	err = ioutil.WriteFile(fmt.Sprintf("%s/pki/index.txt", *easyrsaDirPath), indexTxt, 0600)
	return
}

func (openVPNPKI *OpenVPNPKI) easyrsaGenCRL() (err error) {
	err = openVPNPKI.indexTxtUpdate()
	if err != nil {
		return
	}

	secrets, err := openVPNPKI.secretsGetByLabels("index.txt=,type=clientAuth")
	if err != nil {
		return
	}

	var revoked []*RevokedCert

	for _, secret := range secrets.Items {
		if secret.Annotations["revokedAt"] != "" {
			revokedAt, err := time.Parse(indexTxtDateFormat, secret.Annotations["revokedAt"])
			if err != nil {
				log.Warning(err)
			}
			cert, err := decodeCert(secret.Data[certFileName])
			revoked = append(revoked, &RevokedCert{RevokedTime: revokedAt, Cert: cert})
		}
	}

	crl, err := genCRL(revoked, openVPNPKI.CACert, openVPNPKI.CAPrivKeyRSA)
	if err != nil {
		return
	}

	secretMetaData := metav1.ObjectMeta{Name: secretCRL}

	secretData := map[string][]byte{
		"crl.pem": crl.Bytes(),
	}

	//err = openVPNPKI.secretCreate(secretMetaData, secretData)

	if res, _ := openVPNPKI.secretCheckExists(secretCRL); !res {
		err = openVPNPKI.secretCreate(secretMetaData, secretData, v1.SecretTypeOpaque)
	} else {
		err = openVPNPKI.secretUpdate(secretMetaData, secretData, v1.SecretTypeOpaque)
	}

	return
}

func (openVPNPKI *OpenVPNPKI) easyrsaBuildClient(commonName string) (err error) {
	// check certificate exists
	_, err = openVPNPKI.secretGetByLabels("name=" + commonName)
	if err == nil {
		return errors.New(fmt.Sprintf("certificate for user (%s) already exists", commonName))
	}

	clientPrivKeyPEM, err := genPrivKey()
	if err != nil {
		return
	}

	clientPrivKeyRSA, err := decodePrivKey(clientPrivKeyPEM.Bytes())
	if err != nil {
		return
	}

	clientCertPEM, _ := genClientCert(clientPrivKeyRSA, openVPNPKI.CAPrivKeyRSA, openVPNPKI.CACert, commonName)
	clientCert, err := decodeCert(clientCertPEM.Bytes())

	secretMetaData := metav1.ObjectMeta{
		Name: fmt.Sprintf(secretClientTmpl, clientCert.SerialNumber),
		Labels: map[string]string{
			"index.txt":                    "",
			"type":                         "clientAuth",
			"name":                         commonName,
			"app.kubernetes.io/managed-by": "ovpn-admin",
		},
		Annotations: map[string]string{
			"commonName":   commonName,
			"notBefore":    clientCert.NotBefore.Format(indexTxtDateFormat),
			"notAfter":     clientCert.NotAfter.Format(indexTxtDateFormat),
			"revokedAt":    "",
			"serialNumber": fmt.Sprintf("%d", clientCert.SerialNumber),
		},
	}

	secretData := map[string][]byte{
		certFileName:    clientCertPEM.Bytes(),
		privKeyFileName: clientPrivKeyPEM.Bytes(),
	}

	err = openVPNPKI.secretCreate(secretMetaData, secretData, v1.SecretTypeTLS)
	if err != nil {
		return
	}

	err = openVPNPKI.indexTxtUpdate()
	if err != nil {
		return
	}

	err = openVPNPKI.updateIndexTxtOnDisk()

	return
}

func (openVPNPKI *OpenVPNPKI) easyrsaGetCACert() string {
	return openVPNPKI.CACertPEM.String()
}

func (openVPNPKI *OpenVPNPKI) easyrsaGetClientCert(commonName string) (cert, key string) {
	secret, err := openVPNPKI.secretGetByLabels("name=" + commonName)
	if err != nil {
		log.Error(err)
	}

	cert = string(secret.Data[certFileName])
	key = string(secret.Data[privKeyFileName])

	return
}

func (openVPNPKI *OpenVPNPKI) easyrsaRevoke(commonName string) (err error) {
	secret, err := openVPNPKI.secretGetByLabels("name=" + commonName)
	if err != nil {
		log.Error(err)
	}

	if secret.Annotations["revokedAt"] != "" {
		log.Warnf("user (%s) already revoked", commonName)
		return
	}

	secret.Annotations["revokedAt"] = time.Now().Format(indexTxtDateFormat)

	_, err = openVPNPKI.KubeClient.CoreV1().Secrets(namespace).Update(context.TODO(), secret, metav1.UpdateOptions{})
	if err != nil {
		return
	}

	err = openVPNPKI.indexTxtUpdate()
	if err != nil {
		return
	}

	err = openVPNPKI.updateIndexTxtOnDisk()
	if err != nil {
		return
	}

	err = openVPNPKI.easyrsaGenCRL()
	if err != nil {
		log.Error(err)
	}

	err = openVPNPKI.updateCRLOnDisk()

	return
}

func (openVPNPKI *OpenVPNPKI) easyrsaUnrevoke(commonName string) (err error) {
	secret, err := openVPNPKI.secretGetByLabels("name=" + commonName)
	if err != nil {
		log.Error(err)
	}

	secret.Annotations["revokedAt"] = ""

	_, err = openVPNPKI.KubeClient.CoreV1().Secrets(namespace).Update(context.TODO(), secret, metav1.UpdateOptions{})
	if err != nil {
		return
	}

	err = openVPNPKI.indexTxtUpdate()
	if err != nil {
		return
	}

	err = openVPNPKI.updateIndexTxtOnDisk()
	if err != nil {
		return
	}

	err = openVPNPKI.easyrsaGenCRL()
	if err != nil {
		log.Error(err)
	}

	err = openVPNPKI.updateCRLOnDisk()

	return
}

func (openVPNPKI *OpenVPNPKI) easyrsaRotate(commonName, newPassword string) (err error) {
	secret, err := openVPNPKI.secretGetByLabels("name=" + commonName)
	if err != nil {
		log.Error(err)
	}
	uniqHash := strings.Replace(uuid.New().String(), "-", "", -1)
	secret.Annotations["commonName"] = "REVOKED-" + commonName + "-" + uniqHash
	secret.Labels["name"] = "REVOKED" + commonName
	secret.Labels["revokedForever"] = "true"

	_, err = openVPNPKI.KubeClient.CoreV1().Secrets(namespace).Update(context.TODO(), secret, metav1.UpdateOptions{})
	if err != nil {
		return
	}

	err = openVPNPKI.easyrsaBuildClient(commonName)
	if err != nil {
		return
	}

	err = openVPNPKI.transferRoutes(secret, commonName)
	if err != nil {
		return
	}

	err = openVPNPKI.indexTxtUpdate()
	if err != nil {
		return
	}

	err = openVPNPKI.updateIndexTxtOnDisk()
	if err != nil {
		return
	}

	err = openVPNPKI.easyrsaGenCRL()
	if err != nil {
		log.Error(err)
	}

	err = openVPNPKI.updateCRLOnDisk()
	return
}
func (openVPNPKI *OpenVPNPKI) easyrsaDelete(commonName string) (err error) {
	secret, err := openVPNPKI.secretGetByLabels("name=" + commonName)
	if err != nil {
		log.Error(err)
	}
	uniqHash := strings.Replace(uuid.New().String(), "-", "", -1)
	secret.Annotations["commonName"] = "REVOKED-" + commonName + "-" + uniqHash
	secret.Labels["name"] = "REVOKED-" + commonName + "-" + uniqHash
	secret.Labels["revokedForever"] = "true"

	_, err = openVPNPKI.KubeClient.CoreV1().Secrets(namespace).Update(context.TODO(), secret, metav1.UpdateOptions{})
	if err != nil {
		return
	}

	err = openVPNPKI.indexTxtUpdate()
	if err != nil {
		return
	}

	err = openVPNPKI.updateIndexTxtOnDisk()
	if err != nil {
		return
	}

	err = openVPNPKI.easyrsaGenCRL()
	if err != nil {
		log.Error(err)
	}

	err = openVPNPKI.updateCRLOnDisk()
	return
}

func (openVPNPKI *OpenVPNPKI) secretGetClientCert(name string) (cert ClientCert, err error) {
	secret, err := openVPNPKI.secretGetByName(name)
	if err != nil {
		return
	}

	cert.CertPEM = bytes.NewBuffer(secret.Data[certFileName])
	cert.Cert, err = decodeCert(cert.CertPEM.Bytes())
	if err != nil {
		return
	}

	cert.PrivKeyPEM = bytes.NewBuffer(secret.Data[privKeyFileName])
	cert.PrivKeyRSA, err = decodePrivKey(cert.PrivKeyPEM.Bytes())
	if err != nil {
		return
	}

	return
}

func (openVPNPKI *OpenVPNPKI) updateFilesFromSecrets() (err error) {
	ca, err := openVPNPKI.secretGetClientCert(secretCA)
	if err != nil {
		return
	}

	server, err := openVPNPKI.secretGetClientCert(secretServer)
	if err != nil {
		return
	}

	secret, err := openVPNPKI.secretGetByName(secretDHandTA)
	takey := secret.Data["ta.key"]
	dhparam := secret.Data["dh.pem"]

	if _, err := os.Stat(fmt.Sprintf("%s/pki/issued", *easyrsaDirPath)); os.IsNotExist(err) {
		err = os.MkdirAll(fmt.Sprintf("%s/pki/issued", *easyrsaDirPath), 0755)
	}

	if _, err := os.Stat(fmt.Sprintf("%s/pki/private", *easyrsaDirPath)); os.IsNotExist(err) {
		err = os.MkdirAll(fmt.Sprintf("%s/pki/private", *easyrsaDirPath), 0755)
	}

	err = ioutil.WriteFile(fmt.Sprintf("%s/pki/ca.crt", *easyrsaDirPath), ca.CertPEM.Bytes(), 0600)
	if err != nil {
		return
	}

	err = ioutil.WriteFile(fmt.Sprintf("%s/pki/issued/server.crt", *easyrsaDirPath), server.CertPEM.Bytes(), 0600)
	if err != nil {
		return
	}

	err = ioutil.WriteFile(fmt.Sprintf("%s/pki/private/server.key", *easyrsaDirPath), server.PrivKeyPEM.Bytes(), 0600)
	if err != nil {
		return
	}

	err = ioutil.WriteFile(fmt.Sprintf("%s/pki/ta.key", *easyrsaDirPath), takey, 0600)
	if err != nil {
		return
	}

	err = ioutil.WriteFile(fmt.Sprintf("%s/pki/dh.pem", *easyrsaDirPath), dhparam, 0600)
	if err != nil {
		return
	}

	err = openVPNPKI.updateCRLOnDisk()
	return
}

func (openVPNPKI *OpenVPNPKI) updateCRLOnDisk() (err error) {
	secret, err := openVPNPKI.secretGetByName(secretCRL)
	crl := secret.Data["crl.pem"]
	err = ioutil.WriteFile(fmt.Sprintf("%s/pki/crl.pem", *easyrsaDirPath), crl, 0644)
	if err != nil {
		log.Errorf("error write crl.pem:%s", err.Error())
	}
	return
}

func (openVPNPKI *OpenVPNPKI) secretGenTaKeyAndDHParam() (err error) {
	taKeyPath := "/tmp/ta.key"
	cmd := exec.Command("bash", "-c", fmt.Sprintf("/usr/sbin/openvpn --genkey --secret %s", taKeyPath))
	stdout, err := cmd.CombinedOutput()
	log.Info(fmt.Sprintf("/usr/sbin/openvpn --genkey --secret %s: %s", taKeyPath, string(stdout)))
	if err != nil {
		return
	}
	taKey, err := ioutil.ReadFile(taKeyPath)

	dhparamPath := "/tmp/dh.pem"
	cmd = exec.Command("bash", "-c", fmt.Sprintf("openssl dhparam -out %s 2048", dhparamPath))
	_, err = cmd.CombinedOutput()
	if err != nil {
		return
	}
	dhparam, err := ioutil.ReadFile(dhparamPath)

	secretMetaData := metav1.ObjectMeta{Name: secretDHandTA}

	secretData := map[string][]byte{
		"ta.key": taKey,
		"dh.pem": dhparam,
	}

	err = openVPNPKI.secretCreate(secretMetaData, secretData, v1.SecretTypeOpaque)
	if err != nil {
		return
	}

	return
}

// ccd

func (openVPNPKI *OpenVPNPKI) secretGetCcd(commonName string) (ccd string) {
	secret, err := openVPNPKI.secretGetByLabels("name=" + commonName)
	if err != nil {
		log.Error(err)
		return
	}

	for k, _ := range secret.Data {
		if k == "ccd" {
			ccd = string(secret.Data["ccd"])
			return
		}
	}
	return
}

func (openVPNPKI *OpenVPNPKI) secretUpdateCcd(commonName string, ccd []byte) {
	secret, err := openVPNPKI.secretGetByLabels("name=" + commonName)
	if err != nil {
		log.Error(err)
		return
	}
	secret.Data["ccd"] = ccd

	err = openVPNPKI.secretUpdate(secret.ObjectMeta, secret.Data, v1.SecretTypeTLS)
	if err != nil {
		log.Errorf("secret (%s) update error: %s", secret.Name, err.Error())
	}

	err = openVPNPKI.updateCcdOnDisk()
	if err != nil {
		log.Error(err)
	}
}

func (openVPNPKI *OpenVPNPKI) updateCcdOnDisk() (err error) {
	secrets, err := openVPNPKI.secretsGetByLabels("index.txt=,type=clientAuth")
	if err != nil {
		return
	}

	if _, err := os.Stat(*ccdDir); os.IsNotExist(err) {
		err = os.MkdirAll(*ccdDir, 0755)
	}

	for _, secret := range secrets.Items {
		ccd := secret.Data["ccd"]
		if len(ccd) > 0 {
			err = ioutil.WriteFile(fmt.Sprintf("%s/%s", *ccdDir, secret.Labels["name"]), ccd, 0644)
			if err != nil {
				log.Error(err)
			}
		}
	}

	return
}

//

func (openVPNPKI *OpenVPNPKI) secretCreate(objectMeta metav1.ObjectMeta, data map[string][]byte, secretType v1.SecretType) (err error) {
	if objectMeta.Name == "nil" {
		err = errors.New("secret name not defined")
		return
	}

	secret := &v1.Secret{
		TypeMeta:   metav1.TypeMeta{},
		ObjectMeta: objectMeta,
		Data:       data,
		Type:       secretType,
	}
	_, err = openVPNPKI.KubeClient.CoreV1().Secrets(namespace).Create(context.TODO(), secret, metav1.CreateOptions{})
	return
}

func (openVPNPKI *OpenVPNPKI) secretUpdate(objectMeta metav1.ObjectMeta, data map[string][]byte, secretType v1.SecretType) (err error) {
	secret := &v1.Secret{
		TypeMeta:   metav1.TypeMeta{},
		ObjectMeta: objectMeta,
		Data:       data,
		Type:       secretType,
	}
	_, err = openVPNPKI.KubeClient.CoreV1().Secrets(namespace).Update(context.TODO(), secret, metav1.UpdateOptions{})
	return
}

func (openVPNPKI *OpenVPNPKI) secretGetByName(name string) (secret *v1.Secret, err error) {
	secret, err = openVPNPKI.KubeClient.CoreV1().Secrets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	return
}

func (openVPNPKI *OpenVPNPKI) secretsGetByLabels(labels string) (secrets *v1.SecretList, err error) {
	secrets, err = openVPNPKI.KubeClient.CoreV1().Secrets(namespace).List(context.TODO(), metav1.ListOptions{LabelSelector: labels})
	if err != nil {
		return
	}

	if len(secrets.Items) == 0 {
		log.Debugf("secrets with labels %s not found", labels)
	}

	return
}

func (openVPNPKI *OpenVPNPKI) secretGetByLabels(labels string) (secret *v1.Secret, err error) {
	secrets, err := openVPNPKI.secretsGetByLabels(labels)
	if err != nil {
		return
	}

	if len(secrets.Items) > 1 {
		err = errors.New(fmt.Sprintf("found more than one secret with labels %s", labels))
		return
	}

	if len(secrets.Items) == 0 {
		err = errors.New(fmt.Sprintf("secret not found"))
		return
	}

	secret = &secrets.Items[0]

	return
}

func (openVPNPKI *OpenVPNPKI) secretCheckExists(name string) (bool, string) {
	secret, err := openVPNPKI.KubeClient.CoreV1().Secrets(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		log.Debug(err)
		return false, ""
	}
	return true, secret.ResourceVersion
}

// transferRoutes transfers configured routes from revoked certs to a new one
func (openVPNPKI *OpenVPNPKI) transferRoutes(revokedSecret *v1.Secret, newNameCert string) error {
	ccd, ok := revokedSecret.Data["ccd"]
	if !ok || len(ccd) == 0 {
		log.Infof("No CCD data found in secret %s", revokedSecret.Name)
		return nil
	}

	openVPNPKI.secretUpdateCcd(newNameCert, ccd)

	return nil
}
