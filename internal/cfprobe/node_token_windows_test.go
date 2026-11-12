//go:build windows

package cfprobe

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestNodeTokenWindowsPrivateACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.conf")
	if err := writeConfig(path, Config{NodeToken: testNodeToken}); err != nil {
		t.Fatal(err)
	}
	f, err := openNodeTokenFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyPrivateFile(f); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, _ := sd.DACL()
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := readNodeTokenFile(path); err == nil {
		t.Fatal("public Windows token file accepted")
	}
	if _, err := readConfig(path); err == nil {
		t.Fatal("public Windows config accepted despite 0600")
	}
	// Restore a private ACL before the temporary directory cleanup.
	f, err = os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := protectPrivateFile(f); err != nil {
		t.Fatal(err)
	}
}

func TestNodeTokenWindowsReplaceableParent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.conf")
	if err := writeConfig(path, Config{NodeToken: testNodeToken}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	original, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	defer windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, original, nil)
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	for _, rights := range []string{"0x40", "0x2", "0x4", "SD", "WD", "WO"} {
		t.Run(rights, func(t *testing.T) {
			unsafeSD, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FA;;;BA)(A;;FA;;;SY)(A;;" + rights + ";;;WD)")
			if err != nil {
				t.Fatal(err)
			}
			acl, _, _ := unsafeSD.DACL()
			if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
				t.Fatal(err)
			}
			if err := verifyPrivateParent(path); err == nil {
				t.Fatal("replaceable Windows parent accepted")
			}
			if _, err := readConfig(path); err == nil {
				t.Fatal("private DACL failed to protect replaceable config path")
			}
			if err := writeConfig(path, Config{NodeToken: testNodeToken, Name: "changed"}); err == nil {
				t.Fatal("unsafe parent permitted replacement")
			}
			after, _ := os.ReadFile(path)
			if string(before) != string(after) {
				t.Fatal("failed protection changed working config")
			}
		})
	}
}

func TestNodeTokenWindowsExplicitReinstallPublicConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.conf")
	traffic := filepath.Join(dir, "traffic.dat")
	old := []byte("SECRET=old\nSERVER_ID=untrusted\nWORKER_URL=https://attacker.invalid/update\nTERMINAL_ENABLED=1\n")
	if err := writePrivateTestFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(traffic, []byte("preserved"), 0600); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, _ := sd.DACL()
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	existing, _, existingErr := readInstallConfig(Paths{ConfigFile: path})
	if existingErr == nil || errors.Is(existingErr, errLegacyCredential) || existing.NodeToken != "" || existing.WorkerURL != "" || existing.ServerID != "" {
		t.Fatal("unsafe config was read rather than rejected")
	}
	opts := InstallOptions{Config: Config{NodeToken: testNodeToken, ServerID: "node", WorkerURL: "http://invalid/update"}, Explicit: map[string]bool{"token": true, "url": true, "id": true}}
	if err := prepareInstallCredentials(&opts, existing, existingErr); err == nil {
		t.Fatal("invalid replacement accepted")
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(old) {
		t.Fatal("failed validation modified rejected config")
	}
	opts.Config.WorkerURL = "https://example.com/update"
	if err := prepareInstallCredentials(&opts, existing, existingErr); err != nil {
		t.Fatal(err)
	}
	if opts.TerminalEnabled || opts.ServerID != "node" || opts.ReportInterval != defaultReportIntervalSec {
		t.Fatal("unsafe old options reused")
	}
	if err := writeConfig(path, opts.Config); err != nil {
		t.Fatal(err)
	}
	saved, err := readConfig(path)
	if err != nil || saved.NodeToken != testNodeToken {
		t.Fatal("safe replacement did not restore readable config", err)
	}
	data, _ := os.ReadFile(traffic)
	if string(data) != "preserved" {
		t.Fatal("recovery changed traffic data")
	}
}

func TestNodeTokenWindowsParentACLPolicy(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		ace                string
		immediate, allowed bool
	}{
		{"(A;;FR;;;WD)", true, true},
		{"(A;IO;FA;;;WD)", true, true},
		{"(A;;0x4;;;WD)", false, true},
		{"(A;;0x4;;;WD)", true, false},
		{"(A;;0x40;;;WD)", false, false},
		{"(A;;SD;;;WD)", false, false},
		{"(A;;WD;;;WD)", false, false},
		{"(A;;WO;;;WD)", false, false},
		{"(A;;GA;;;WD)", false, false},
	} {
		sd, err := windows.SecurityDescriptorFromString("O:" + user.User.Sid.String() + "D:P(A;;FA;;;" + user.User.Sid.String() + ")" + tc.ace)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateWindowsParentSecurity(sd, tc.immediate); (err == nil) != tc.allowed {
			t.Fatalf("ACE %s immediate=%v allowed=%v err=%v", tc.ace, tc.immediate, tc.allowed, err)
		}
	}
	sd, err := windows.SecurityDescriptorFromString("O:WDD:P(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateWindowsParentSecurity(sd, false); err == nil {
		t.Fatal("untrusted parent owner accepted")
	}
}
