package server

import (
	"crypto/x509"
	"encoding/json"
	"errors"

	"github.com/samber/lo"
	"github.com/wakeful-cloud/pam-oauth/internal/common"
)

// certificateAllowList is the client certificate allow list indexed by the certificate signature
type certificateAllowList struct {
	entries map[string]*x509.Certificate
}

// newCertificateAllowList creates a new certificate allow list
func newCertificateAllowList() certificateAllowList {
	return certificateAllowList{
		entries: map[string]*x509.Certificate{},
	}
}

// GetEntries gets the entries in the certificate allow list
func (list certificateAllowList) GetEntries() []*x509.Certificate {
	return lo.Values(list.entries)
}

// Add adds an entry to the certificate allow list
func (list certificateAllowList) Add(cert *x509.Certificate) error {
	// Enforce unique entries
	for _, entry := range list.entries {
		if entry.Equal(cert) {
			return errors.New("entry already exists")
		}
	}

	// Add the entry
	list.entries[string(cert.Signature)] = cert

	return nil
}

// Check checks if an entry is in the certificate allow list
func (list certificateAllowList) Check(cert *x509.Certificate) (bool, error) {
	// Get the entry
	entry, ok := list.entries[string(cert.Signature)]

	if !ok {
		return false, nil
	}

	// Check if the entry matches
	return entry.Equal(cert), nil
}

// Remove removes entries from the certificate allow list
func (list certificateAllowList) Remove(filter func(entry *x509.Certificate) (bool, error)) error {
	// Remove the entries
	for signature, entry := range list.entries {
		ok, err := filter(entry)

		if err != nil {
			return err
		}

		if ok {
			delete(list.entries, signature)
		}
	}

	return nil
}

// MarshalJSON marshals a certificate allow list
func (list certificateAllowList) MarshalJSON() ([]byte, error) {
	// Convert each certificate to its PEM-encoded form
	entries := []string{}

	for _, entry := range list.entries {
		pem, err := common.EncodeCert(entry.Raw)

		if err != nil {
			return nil, err
		}

		entries = append(entries, string(pem))
	}

	// Marshal the entries
	return json.Marshal(entries)
}

// UnmarshalJSON unmarshals a certificate allow list
func (list *certificateAllowList) UnmarshalJSON(data []byte) error {
	// Unmarshal the entries
	var entries []string
	err := json.Unmarshal(data, &entries)

	if err != nil {
		return err
	}

	// Convert each PEM-encoded certificate to its x509 form
	list.entries = map[string]*x509.Certificate{}

	for _, entry := range entries {
		block, err := common.DecodeCert([]byte(entry))

		if err != nil {
			return err
		}

		cert, err := x509.ParseCertificate(block.Bytes)

		if err != nil {
			return err
		}

		list.entries[string(cert.Signature)] = cert
	}

	return nil
}

// SaveCertificateAllowList saves a certificate allow list file
func SaveCertificateAllowList(list certificateAllowList, name string, relative string, mode common.SafeOpenMode) error {
	// Marshal the list
	raw, err := json.Marshal(list)

	if err != nil {
		return err
	}

	// Write the file
	err = common.SafeCreate(name, relative, raw, common.PROTECTED_FILE_MODE, common.PROTECTED_FOLDER_MODE, mode)

	if err != nil {
		return err
	}

	return nil
}

// LoadCertificateAllowList loads a certificate allow list file
func LoadCertificateAllowList(name string, relative string) (certificateAllowList, error) {
	// Read the file
	raw, err := common.SafeRead(name, relative)

	if err != nil {
		return certificateAllowList{}, err
	}

	// Unmarshal the file
	var list certificateAllowList
	err = json.Unmarshal(raw, &list)

	if err != nil {
		return certificateAllowList{}, err
	}

	return list, nil
}
