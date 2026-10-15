package main

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

// clientSecret builds a client certificate secret as easyrsaBuildClient creates it.
// ccd == nil means the secret has no "ccd" key.
func clientSecret(name, user string, ccd *string, revokedForever bool) *v1.Secret {
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels: map[string]string{
				labelKeyIndexTxt:  "",
				labelKeyType:      labelValueClientAuth,
				labelKeyName:      user,
				labelKeyManagedBy: labelValueManagedByApp,
			},
		},
		Data: map[string][]byte{certFileName: []byte("cert"), privKeyFileName: []byte("key")},
		Type: v1.SecretTypeTLS,
	}
	if ccd != nil {
		secret.Data["ccd"] = []byte(*ccd)
	}
	if revokedForever {
		secret.Labels["revokedForever"] = "true"
	}
	return secret
}

func strPtr(s string) *string { return &s }

// setupKubeTest switches to the kubernetes.secrets backend with a fake API server.
func setupKubeTest(t *testing.T, secrets ...*v1.Secret) (*fake.Clientset, string) {
	t.Helper()
	objects := make([]runtime.Object, 0, len(secrets))
	for _, s := range secrets {
		objects = append(objects, s)
	}
	client := fake.NewClientset(objects...)

	oldClient := app.KubeClient
	app.KubeClient = client
	t.Cleanup(func() { app.KubeClient = oldClient })

	dir := t.TempDir()
	setFlag(t, storageBackend, "kubernetes.secrets")
	setFlag(t, ccdDir, dir)
	setFlag(t, ccdTemplatePath, "")
	return client, dir
}

func TestStaticAddressesInUseKubernetes(t *testing.T) {
	setNetworks(t, "172.16.100.0/24", "fd00:16:100::/64")
	// created without the managed-by label: its ccd is written to disk all the same
	frank := clientSecret("openvpn-pki-6", "frank", strPtr("ifconfig-push 172.16.100.60 255.255.255.0\n"), false)
	delete(frank.Labels, labelKeyManagedBy)
	setupKubeTest(t,
		frank,
		clientSecret("openvpn-pki-1", "alice", strPtr("ifconfig-push 172.16.100.10 255.255.255.0\nifconfig-ipv6-push fd00:16:100::10/64\n"), false),
		clientSecret("openvpn-pki-2", "bob", strPtr("ifconfig-push 172.16.100.20 255.255.255.0\nifconfig-ipv6-push FD00:16:100:0:0:0:0:20/64\n"), false),
		// a rotated/deleted certificate keeps a copy of the ccd and must not block its addresses
		clientSecret("openvpn-pki-3", "REVOKEDcarol", strPtr("ifconfig-push 172.16.100.30 255.255.255.0\n"), true),
		clientSecret("openvpn-pki-4", "dave", nil, false),
		clientSecret("openvpn-pki-5", "erin", strPtr(""), false),
	)

	got, err := staticAddressesInUse("alice")
	if err != nil {
		t.Fatal(err)
	}
	want := map[netip.Addr]string{
		netip.MustParseAddr("172.16.100.20"):   "bob",
		netip.MustParseAddr("fd00:16:100::20"): "bob",
		netip.MustParseAddr("172.16.100.60"):   "frank",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("staticAddressesInUse(alice) = %v, want %v", got, want)
	}
}

func TestValidateCcdUniquenessKubernetes(t *testing.T) {
	setNetworks(t, "172.16.100.0/24", "fd00:16:100::/64")
	setupUsers(t, "alice", "bob")
	setupKubeTest(t,
		clientSecret("openvpn-pki-1", "alice", strPtr("ifconfig-push 172.16.100.10 255.255.255.0\n"), false),
		clientSecret("openvpn-pki-2", "bob", strPtr("ifconfig-push 172.16.100.20 255.255.255.0\nifconfig-ipv6-push fd00:16:100::20/64\n"), false),
		clientSecret("openvpn-pki-3", "REVOKEDbob", strPtr("ifconfig-push 172.16.100.30 255.255.255.0\n"), true),
	)

	tests := []struct {
		name    string
		ccd     Ccd
		wantErr bool
	}{
		{"own address", Ccd{User: "alice", ClientAddress: "172.16.100.10"}, false},
		{"address of a rotated certificate", Ccd{User: "alice", ClientAddress: "172.16.100.30"}, false},
		{"IPv4 address of another user", Ccd{User: "alice", ClientAddress: "172.16.100.20"}, true},
		{"IPv6 address of another user in another notation", Ccd{User: "alice", ClientAddressIPv6: "FD00:16:100:0::20"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validateCcd(tt.ccd)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCcd(%+v) error = %v, wantErr %v", tt.ccd, err, tt.wantErr)
			}
		})
	}
}

func TestModifyCcdKubernetesClearsStaticAddress(t *testing.T) {
	setNetworks(t, "172.16.100.0/24", "")
	setupUsers(t, "alice", "bob")
	client, dir := setupKubeTest(t,
		clientSecret("openvpn-pki-1", "alice", strPtr("ifconfig-push 172.16.100.10 255.255.255.0\n"), false),
		clientSecret("openvpn-pki-2", "bob", nil, false),
	)
	// the file written to the shared ccd dir when the static address was assigned
	if err := os.WriteFile(filepath.Join(dir, "alice"), []byte("ifconfig-push 172.16.100.10 255.255.255.0\n"), 0644); err != nil {
		t.Fatal(err)
	}

	oAdmin := &OvpnAdmin{}
	if ok, msg := oAdmin.modifyCcd(Ccd{User: "alice", ClientAddress: "dynamic", ClientAddressIPv6: "dynamic"}); !ok {
		t.Fatalf("modifyCcd(alice dynamic) = %v, %q", ok, msg)
	}

	secret, err := client.CoreV1().Secrets(namespace).Get(context.TODO(), "openvpn-pki-1", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if ccd, ok := secret.Data["ccd"]; !ok || len(ccd) != 0 {
		t.Errorf("secret ccd = %q (present %v), want empty", ccd, ok)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "alice")); err != nil || len(got) != 0 {
		t.Errorf("ccd file of alice = %q, %v; want an empty file", got, err)
	}

	// the released address can be assigned to another user, and OpenVPN does not hand it out twice
	if ok, msg := oAdmin.modifyCcd(Ccd{User: "bob", ClientAddress: "172.16.100.10"}); !ok {
		t.Fatalf("modifyCcd(bob 172.16.100.10) = %v, %q", ok, msg)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "bob")); string(got) != "ifconfig-push 172.16.100.10 255.255.255.0\n" {
		t.Errorf("ccd file of bob = %q", got)
	}
}

func TestModifyCcdKubernetesReportsErrors(t *testing.T) {
	setNetworks(t, "172.16.100.0/24", "")
	// the user is in index.txt, but its secret is missing
	setupUsers(t, "ghost")
	setupKubeTest(t)

	oAdmin := &OvpnAdmin{}
	ok, msg := oAdmin.modifyCcd(Ccd{User: "ghost", CustomRoutes: []ccdRoute{{Address: "10.0.0.0", Mask: "255.0.0.0"}}})
	if ok || msg != "failed to write ccd" {
		t.Errorf("modifyCcd() = %v, %q; want false, %q", ok, msg, "failed to write ccd")
	}
}
