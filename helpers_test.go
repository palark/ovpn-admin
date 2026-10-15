package main

import (
	"archive/tar"
	"compress/gzip"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setFlag sets a package-level flag value for the duration of a test.
func setFlag[T any](t *testing.T, flag *T, value T) {
	t.Helper()
	old := *flag
	*flag = value
	t.Cleanup(func() { *flag = old })
}

// setNetworks sets the parsed OpenVPN pools for the duration of a test; v6 == "" disables IPv6.
func setNetworks(t *testing.T, v4, v6 string) {
	t.Helper()
	oldV4, oldV6 := ovpnNetworkV4, ovpnNetworkV6
	t.Cleanup(func() { ovpnNetworkV4, ovpnNetworkV6 = oldV4, oldV6 })

	ovpnNetworkV4 = netip.MustParsePrefix(v4)
	ovpnNetworkV6 = netip.Prefix{}
	if v6 != "" {
		ovpnNetworkV6 = netip.MustParsePrefix(v6)
	}
}

// setupUsers writes an index.txt with the given users and points --easyrsa.index-path to it.
func setupUsers(t *testing.T, users ...string) {
	t.Helper()
	var b strings.Builder
	for i, u := range users {
		b.WriteString("V\t351231235959Z\t\t0" + string(rune('1'+i)) + "\tunknown\t/CN=" + u + "\n")
	}
	path := filepath.Join(t.TempDir(), "index.txt")
	if err := os.WriteFile(path, []byte(b.String()), 0644); err != nil {
		t.Fatal(err)
	}
	setFlag(t, indexTxtPath, path)
}

// setupCcdDir creates a ccd dir with the given files and points --ccd.path to it.
func setupCcdDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	setFlag(t, ccdDir, dir)
	setFlag(t, storageBackend, "filesystem")
	setFlag(t, ccdTemplatePath, "")
	return dir
}

func TestRedactArgs(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"create", "--db.path", "/db", "--user", "alice", "--password", "secret"}, "create --db.path /db --user alice --password ******"},
		{[]string{"create", "--db.path=/db", "--user=alice", "--password=-Secret123"}, "create --db.path=/db --user=alice --password=******"},
		{[]string{"change-password", "--user=alice", "--password="}, "change-password --user=alice --password=******"},
	}
	for _, tt := range tests {
		if got := strings.Join(redactArgs(tt.args), " "); got != tt.want {
			t.Errorf("redactArgs(%q) = %q, want %q", tt.args, got, tt.want)
		}
	}
}

func TestOvpnUserListHasUser(t *testing.T) {
	// real "openvpn-user list --all" output of 1.0.9 and 1.0.4
	const list109 = "id | username | revoked | deleted | app_configured\n" +
		"1  | alice    | false   | false   | false\n" +
		"2  | bob      | true    | false   | false\n"
	const list104 = "id | username | revoked | deleted\n" +
		"1  | alice    | false   | false\n"
	tests := []struct {
		out, user string
		want      bool
	}{
		{list109, "alice", true},
		{list109, "bob", true}, // revoked users have a row as well
		{list109, "carol", false},
		{list109, "username", false}, // header
		{list109, "ali", false},
		{list104, "alice", true},
		{strings.ReplaceAll(list109, "\n", "\r\n"), "bob", true},
		{"No users created yet\n", "alice", false},
		{"", "alice", false},
		{"no such table: users\n", "users", false},
	}
	for _, tt := range tests {
		if got := ovpnUserListHasUser(tt.out, tt.user); got != tt.want {
			t.Errorf("ovpnUserListHasUser(%q, %q) = %v, want %v", tt.out, tt.user, got, tt.want)
		}
	}
}

func TestRunCommandDoesNotUseShell(t *testing.T) {
	dir := t.TempDir()
	out, err := runCommand(dir, "", "echo", "$(id)", ";", "`id`", "|", "wc")
	if err != nil {
		t.Skipf("echo is not available: %v", err)
	}
	if strings.TrimSpace(out) != "$(id) ; `id` | wc" {
		t.Errorf("arguments were interpreted: %q", out)
	}
}

func TestUsernameIsPathSafe(t *testing.T) {
	tests := map[string]bool{
		"alice":            true,
		"alice.smith@corp": true,
		"":                 false,
		".":                false,
		"..":               false,
		"../etc/passwd":    false,
		"a/b":              false,
		`a\b`:              false,
		"a\x00b":           false,
	}
	for name, want := range tests {
		if got := usernameIsPathSafe(name); got != want {
			t.Errorf("usernameIsPathSafe(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestValidateUsername(t *testing.T) {
	for _, name := range []string{"alice", "bob_1", "a.b-c@d"} {
		if err := validateUsername(name); err != nil {
			t.Errorf("validateUsername(%q) = %v, want nil", name, err)
		}
	}
	for _, name := range []string{"", ".", "..", "../x", "a/b", "a b", "a\nb", `a\b`} {
		if err := validateUsername(name); err == nil {
			t.Errorf("validateUsername(%q) = nil, want error", name)
		}
	}
}

func TestIndexTxtParserShortLines(t *testing.T) {
	lines := indexTxtParser("V\t351231235959Z\n" +
		"R\t351231235959Z\t240101000000Z\t02\n" +
		"V\t351231235959Z\t\t01\tunknown\t/CN=alice\n" +
		"R\t351231235959Z\t240101000000Z\t02\tunknown\t/CN=bob\n")
	if len(lines) != 2 || lines[0].Identity != "alice" || lines[1].Identity != "bob" {
		t.Errorf("indexTxtParser() = %+v", lines)
	}
}

func TestExtractFromArchiveRejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "evil.tar.gz")

	f, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	content := []byte("pwned")
	if err := tw.WriteHeader(&tar.Header{Name: "../evil", Mode: 0644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gw.Close()
	f.Close()

	dest := filepath.Join(dir, "dest")
	if err := os.Mkdir(dest, 0755); err != nil {
		t.Fatal(err)
	}
	if err := extractFromArchive(archive, dest); err == nil {
		t.Fatal("extractFromArchive() = nil, want error for ../evil")
	}
	if _, err := os.Stat(filepath.Join(dir, "evil")); err == nil {
		t.Fatal("file was written outside of the destination directory")
	}
}

func TestExtractFromArchiveCreatesSubdirs(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(filepath.Join(src, "issued"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "issued", "alice.crt"), []byte("cert"), 0644); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "certs.tar.gz")
	if err := createArchiveFromDir(src, archive); err != nil {
		t.Fatal(err)
	}

	dest := filepath.Join(dir, "dest")
	if err := os.Mkdir(dest, 0755); err != nil {
		t.Fatal(err)
	}
	if err := extractFromArchive(archive, dest); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dest, "issued", "alice.crt")); string(got) != "cert" {
		t.Errorf("extracted content = %q, want %q", got, "cert")
	}
}

func TestCreateArchiveFromRelativeDir(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.MkdirAll(filepath.Join("ccd"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("ccd", "alice"), []byte("ifconfig-push 172.16.100.10 255.255.255.0\n"), 0644); err != nil {
		t.Fatal(err)
	}

	for _, src := range []string{"./ccd", "ccd", "./ccd/"} {
		archive := filepath.Join(dir, "ccd.tar.gz")
		if err := createArchiveFromDir(src, archive); err != nil {
			t.Fatalf("createArchiveFromDir(%q): %v", src, err)
		}
		dest := t.TempDir()
		if err := extractFromArchive(archive, dest); err != nil {
			t.Fatalf("extractFromArchive() for %q: %v", src, err)
		}
		if _, err := os.Stat(filepath.Join(dest, "alice")); err != nil {
			t.Errorf("archive of %q: alice is not at the archive root: %v", src, err)
		}
	}
}
