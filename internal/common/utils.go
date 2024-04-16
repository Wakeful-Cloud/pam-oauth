package common

import (
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
)

// CHALLENGE_ID_LENGTH is the length of the challenge ID (in bytes)
const CHALLENGE_ID_LENGTH = 32

// CHALLENGE_STATE_LENGTH is the length of the challenge OAuth state (in bytes)
const CHALLENGE_STATE_LENGTH = 32

// VERIFICATION_CODE_LENGTH is the length of the code (in decimal digits)
const VERIFICATION_CODE_LENGTH = 6

const (
	// PROTECTED_FILE_MODE is the expected file mode for protected files
	PROTECTED_FILE_MODE = 0o600

	// PROTECTED_FOLDER_MODE is the expected file mode for protected folders
	PROTECTED_FOLDER_MODE = 0o755
)

// SafeOpenMode is the mode to open a file
type SafeOpenMode int

const (
	// SAFE_OPEN_MODE_EXCL is the mode to create a new file, requiring that the file does not already exist
	SAFE_OPEN_MODE_EXCL SafeOpenMode = iota

	// SAFE_OPEN_MODE_APPEND is the mode to open a file for appending, creating the file if it does not exist
	SAFE_OPEN_MODE_APPEND

	// SAFE_OPEN_MODE_TRUNCATE is the mode to open a file for writing, creating the file if it does not exist and truncating it if it does
	SAFE_OPEN_MODE_TRUNCATE
)

// DecodeCert decodes a certificate from a PEM-encoded byte array
func DecodeCert(raw []byte) (*pem.Block, error) {
	block, _ := pem.Decode(raw)

	if block == nil {
		return nil, errors.New("invalid PEM block")
	}

	if block.Type != "CERTIFICATE" {
		return nil, errors.New("invalid PEM block type")
	}

	return block, nil
}

// DecodeKey decodes a private key from a PEM-encoded byte array
func DecodeKey(raw []byte) (*pem.Block, error) {
	block, _ := pem.Decode(raw)

	if block == nil {
		return nil, errors.New("invalid PEM block")
	}

	if block.Type != "PRIVATE KEY" {
		return nil, errors.New("invalid PEM block type")
	}

	return block, nil
}

// EncodeCert encodes a certificate into a PEM-encoded byte array
func EncodeCert(raw []byte) ([]byte, error) {
	buffer := bytes.Buffer{}
	err := pem.Encode(&buffer, &pem.Block{Type: "CERTIFICATE", Bytes: raw})

	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

// EncodeKey encodes a private key into a PEM-encoded byte array
func EncodeKey(raw []byte) ([]byte, error) {
	buffer := bytes.Buffer{}
	err := pem.Encode(&buffer, &pem.Block{Type: "PRIVATE KEY", Bytes: raw})

	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

// EnsureProtectedFile ensures that the file at the specified path is protected
func EnsureProtectedFile(name string, relative string) error {
	// Make the path absolute
	if !filepath.IsAbs(name) {
		name = filepath.Join(relative, name)
	}

	// Clean the path
	name = filepath.Clean(name)

	// Verify the file permissions
	stat, err := os.Stat(name)

	if errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}

	if stat.Mode()&0077 != 0 {
		fmt.Fprintf(os.Stderr, "file at \"%s\" has invalid permissions, stack trace:\n%s\n", name, debug.Stack())

		return fmt.Errorf("file at \"%s\" has invalid permissions", name)
	}

	return nil
}

// MakeDirs makes the directories for the specified path
func MakeDirs(name string, relative string, folderPerm os.FileMode) error {
	// Make the path absolute
	if !filepath.IsAbs(name) {
		name = filepath.Join(relative, name)
	}

	// Clean the path
	name = filepath.Clean(name)

	// Create the parent directories
	return os.MkdirAll(name, folderPerm)
}

// SafeOpen safely opens a new file handle
func SafeOpen(name string, relative string, filePerm os.FileMode, folderPerm os.FileMode, mode SafeOpenMode) (*os.File, error) {
	// Make the parent directories
	err := MakeDirs(filepath.Dir(name), relative, folderPerm)

	if err != nil {
		return nil, err
	}

	// Get the mode
	openMode := 0

	switch mode {
	case SAFE_OPEN_MODE_EXCL:
		openMode = os.O_CREATE | os.O_WRONLY | os.O_EXCL
	case SAFE_OPEN_MODE_APPEND:
		openMode = os.O_CREATE | os.O_WRONLY | os.O_APPEND
	case SAFE_OPEN_MODE_TRUNCATE:
		openMode = os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	}

	// Make the path absolute
	if !filepath.IsAbs(name) {
		name = filepath.Join(relative, name)
	}

	// Clean the path
	name = filepath.Clean(name)

	// Open the file
	// #nosec G304
	file, err := os.OpenFile(name, openMode, filePerm)

	if err != nil {
		return nil, err
	}

	return file, nil
}

// SafeCreate safely creates a new file with the specified data
func SafeCreate(name string, relative string, data []byte, filePerm os.FileMode, folderPerm os.FileMode, mode SafeOpenMode) error {
	// Open the file
	file, err := SafeOpen(name, relative, filePerm, folderPerm, mode)

	if err != nil {
		return err
	}

	defer file.Close()

	// Write the data
	_, err = file.Write(data)

	if err != nil {
		return err
	}

	return nil
}

// SafeRead reads a file safely
func SafeRead(name string, relative string) ([]byte, error) {
	// Make the path absolute
	if !filepath.IsAbs(name) {
		name = filepath.Join(relative, name)
	}

	// Clean the path
	name = filepath.Clean(name)

	// Read the file
	return os.ReadFile(name)
}
