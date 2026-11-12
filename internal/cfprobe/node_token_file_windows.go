//go:build windows

package cfprobe

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func openNodeTokenFile(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		windows.CloseHandle(h)
		return nil, errors.New("credential file must not be a reparse point")
	}
	return os.NewFile(uintptr(h), path), nil
}

func validatePrivateFileInfo(info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return errors.New("credential file must be regular")
	}
	return nil
}

func verifyPrivateParent(path string) error {
	return verifyWindowsParents(path, true)
}

func verifyWindowsParents(path string, immediate bool) error {
	parent, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return err
	}
	for {
		name, err := windows.UTF16PtrFromString(parent)
		if err != nil {
			return err
		}
		h, err := windows.CreateFile(name, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
				return os.ErrNotExist
			}
			return errors.New("cannot verify private credential parent")
		}
		var info windows.ByHandleFileInformation
		infoErr := windows.GetFileInformationByHandle(h, &info)
		sd, aclErr := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
		windows.CloseHandle(h)
		if infoErr != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || aclErr != nil {
			return errors.New("cannot verify regular credential parent")
		}
		if err := validateWindowsParentSecurity(sd, immediate); err != nil {
			return err
		}
		next := filepath.Dir(parent)
		if next == parent {
			return nil
		}
		parent = next
		immediate = false
	}
}

func validateWindowsParentSecurity(sd *windows.SECURITY_DESCRIPTOR, immediate bool) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	trusted := func(sid *windows.SID) bool {
		return sid != nil && (sid.Equals(user.User.Sid) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid))
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return errors.New("cannot verify credential parent owner")
	}
	// Windows system roots are owned by the OS servicing identity, not ordinary users.
	installer, err := windows.StringToSid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
	if err != nil || !trusted(owner) && !owner.Equals(installer) {
		return errors.New("credential parent has an untrusted owner")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return errors.New("credential parent has no verifiable ACL")
	}
	const fileDeleteChild = 0x40
	mask := windows.ACCESS_MASK(fileDeleteChild | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL)
	if immediate {
		mask |= windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil || ace == nil {
			return errors.New("cannot verify parent ACL entry")
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errors.New("unsupported parent ACL entry")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !trusted(sid) && !sid.Equals(installer) && ace.Mask&mask != 0 {
			return errors.New("credential parent can be replaced or written by another user")
		}
	}
	return nil
}

func verifyPrivateFile(f *os.File) error {
	if info, err := f.Stat(); err != nil || validatePrivateFileInfo(info) != nil {
		return errors.New("credential file must be regular")
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(f.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return errors.New("cannot verify private credential ACL")
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return errors.New("credential file has no owner")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || !(owner.Equals(user.User.Sid) || owner.IsWellKnown(windows.WinLocalSystemSid) || owner.IsWellKnown(windows.WinBuiltinAdministratorsSid)) {
		return errors.New("credential file has untrusted owner")
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return errors.New("credential file has no private ACL")
	}
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errors.New("cannot verify credential ACL entry")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.Equals(user.User.Sid) && !sid.IsWellKnown(windows.WinLocalSystemSid) && !sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			return errors.New("credential file grants access outside user, Administrators and SYSTEM")
		}
	}
	return nil
}

func protectPrivateFile(f *os.File) error {
	path, err := windows.UTF16PtrFromString(f.Name())
	if err != nil {
		return err
	}
	// Go's ordinary file handle lacks WRITE_DAC; bind the ACL handle to the same file.
	h, err := windows.CreateFile(path, windows.GENERIC_READ|windows.READ_CONTROL|windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	aclFile := os.NewFile(uintptr(h), f.Name())
	defer aclFile.Close()
	before, beforeErr := f.Stat()
	after, afterErr := aclFile.Stat()
	if beforeErr != nil || afterErr != nil || !os.SameFile(before, after) || validatePrivateFileInfo(after) != nil {
		return errors.New("credential file changed before ACL protection")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		return err
	}
	return verifyPrivateFile(f)
}

func createPrivateTemp(dir, prefix string) (*os.File, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		return nil, err
	}
	security := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	for i := 0; i < 10; i++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, err
		}
		path := filepath.Join(dir, prefix+hex.EncodeToString(random[:]))
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return nil, err
		}
		// Apply a private DACL at CREATE_NEW, before any other process can open the file.
		h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL|windows.WRITE_DAC, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, &security, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err == windows.ERROR_FILE_EXISTS || err == windows.ERROR_ALREADY_EXISTS {
			continue
		}
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(h), path), nil
	}
	return nil, errors.New("cannot create private temporary credential file")
}

func ensurePrivateConfigDirectory(dir string) error {
	if _, err := os.Lstat(dir); err == nil {
		return verifyPrivateParent(filepath.Join(dir, "config.conf"))
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(dir)
	if parent == dir {
		return errors.New("missing configuration root")
	}
	if _, err := os.Lstat(parent); errors.Is(err, os.ErrNotExist) {
		if err := ensurePrivateConfigDirectory(parent); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err := verifyWindowsParents(filepath.Join(parent, "child"), false); err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	security := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(name, &security); err != nil {
		return err
	}
	return verifyPrivateParent(filepath.Join(dir, "config.conf"))
}
