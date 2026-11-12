package cfprobe

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

// A child test trusts only the fixture CA; production and other tests retain real roots.
func runReportTLSFixture(t *testing.T) bool {
	t.Helper()
	if path := os.Getenv("CFSM_REPORT_TEST_ROOT"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(data) {
			t.Fatal("invalid fixture root")
		}
		x509.SetFallbackRoots(roots)
		return false
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	root := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	server.Close()
	path := filepath.Join(t.TempDir(), "report-root.pem")
	if err := os.WriteFile(path, root, 0600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^"+regexp.QuoteMeta(t.Name())+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), "GODEBUG=x509usefallbackroots=1", "CFSM_REPORT_TEST_ROOT="+path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("TLS report fixture: %v\n%s", err, output)
	}
	return true
}

func writePrivateTestFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_RDWR, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := protectPrivateFile(f); err != nil {
		return err
	}
	_, err = f.Write(data)
	return err
}
