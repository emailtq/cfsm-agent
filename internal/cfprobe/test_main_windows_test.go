//go:build windows

package cfprobe

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestMain(m *testing.M) {
	// The host TEMP grants other accounts modify rights. Isolate fixture permissions,
	// never relax the production parent check or alter the host's ACLs.
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	dir := filepath.Join(home, fmt.Sprintf(".cfsm-task4-fixtures-%d", os.Getpid()))
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	security := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := windows.CreateDirectory(name, &security); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := verifyPrivateParent(filepath.Join(dir, "fixture")); err != nil {
		os.Remove(dir)
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Setenv("TEMP", dir)
	os.Setenv("TMP", dir)
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
