package client

/*
#include <pwd.h>
#include <stdlib.h>
*/
import "C"
import (
	"strings"
	"unsafe"
)

// Passwd is a record in the user database
type Passwd struct {
	// Username
	Name string

	// Hashed passphrase, if shadow database not in use (see shadow.h)
	Passwd string

	// User ID
	Uid int

	// Group ID
	Gid int

	// Real name
	Gecos string

	// Home directory
	Dir string

	// Shell program
	Shell string
}

// GetPwuid returns the record in the user database for the given user ID
func GetPwuid(uid uint) (*Passwd, error) {
	// Get the record
	pw, err := C.getpwuid(C.uid_t(uid))

	if pw == nil {
		return nil, err
	}

	// Convert to Go (Copy the strings because getpw* returns pointers to static memory)
	user := Passwd{
		Name:   strings.Clone(C.GoString(pw.pw_name)),
		Passwd: strings.Clone(C.GoString(pw.pw_passwd)),
		Uid:    int(pw.pw_uid),
		Gid:    int(pw.pw_gid),
		Gecos:  strings.Clone(C.GoString(pw.pw_gecos)),
		Dir:    strings.Clone(C.GoString(pw.pw_dir)),
		Shell:  strings.Clone(C.GoString(pw.pw_shell)),
	}

	return &user, nil
}

// GetPwnam returns the record in the user database for the given username
func GetPwnam(name string) (*Passwd, error) {
	// Conver to C
	cName := C.CString(name)

	// #nosec G103
	defer C.free(unsafe.Pointer(cName))

	// Get the record
	pw, err := C.getpwnam(cName)

	if pw == nil {
		return nil, err
	}

	// Convert to Go (Copy the strings because getpw* returns pointers to static memory)
	user := Passwd{
		Name:   strings.Clone(C.GoString(pw.pw_name)),
		Passwd: strings.Clone(C.GoString(pw.pw_passwd)),
		Uid:    int(pw.pw_uid),
		Gid:    int(pw.pw_gid),
		Gecos:  strings.Clone(C.GoString(pw.pw_gecos)),
		Dir:    strings.Clone(C.GoString(pw.pw_dir)),
		Shell:  strings.Clone(C.GoString(pw.pw_shell)),
	}

	return &user, nil
}
