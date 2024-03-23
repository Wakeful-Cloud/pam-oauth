package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"time"

	"github.com/samber/lo"
	"github.com/wakeful-cloud/pam-oauth/internal/common"
)

// certReq is a certificate request
type certReq struct {
	// Certificate Subject
	Subject pkix.Name

	// DNS Subject Alternative Names (SANs)
	DnsSans []string

	// IP address Subject Alternative Names (SANs)
	IpSans []net.IP

	// Whether or not the certificate is a Root certificate
	Root bool

	// Parent certificate (if not a root certificate)
	ParentCert *x509.Certificate

	// Parent private key (if not a root certificate)
	ParentKey *ecdsa.PrivateKey

	// Key usage
	KeyUsage x509.KeyUsage

	// Extended key usage
	ExtKeyUsage []x509.ExtKeyUsage
}

// certRes is a certificate response
type certRes struct {
	// Raw PEM-encoded certificate
	RawCert []byte

	// Certificate
	Cert *x509.Certificate

	// Raw PEM-encoded private key
	RawKey []byte

	// Private Key
	Key *ecdsa.PrivateKey
}

// generateCert generates a new certificate and private key
func generateCert(req certReq) (*certRes, error) {
	// Generate a new serial number
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)

	if err != nil {
		return nil, err
	}

	// Generate the certificate template
	now := time.Now()
	template := &x509.Certificate{
		BasicConstraintsValid: true,
		DNSNames:              req.DnsSans,
		ExtKeyUsage:           lo.Ternary(req.Root, nil, req.ExtKeyUsage),
		IPAddresses:           req.IpSans,
		IsCA:                  req.Root,
		KeyUsage:              lo.Ternary(req.Root, x509.KeyUsageCRLSign|x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature, req.KeyUsage),
		MaxPathLen:            lo.Ternary(req.Root, 1, -1),
		MaxPathLenZero:        true,
		NotAfter:              now.AddDate(1, 0, 0), // 1 year
		NotBefore:             now,
		PublicKeyAlgorithm:    x509.ECDSA,
		SerialNumber:          serialNumber,
		SignatureAlgorithm:    x509.ECDSAWithSHA512,
		Subject:               req.Subject,
	}

	// Generate the private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	if err != nil {
		return nil, err
	}

	// Create and sign the certificate
	signingCert := lo.Ternary(req.Root, template, req.ParentCert)
	signingPrivateKey := lo.Ternary(req.Root, privateKey, req.ParentKey)
	signingPublicKey := &privateKey.PublicKey
	certDer, err := x509.CreateCertificate(
		rand.Reader,
		template,
		signingCert,
		signingPublicKey,
		signingPrivateKey,
	)

	if err != nil {
		return nil, err
	}

	template.Raw = certDer

	// Encode the certificate and private key
	certPem, err := common.EncodeCert(certDer)

	if err != nil {
		return nil, err
	}

	keyDer, err := x509.MarshalPKCS8PrivateKey(privateKey)

	if err != nil {
		return nil, err
	}

	keyPem, err := common.EncodeKey(keyDer)

	if err != nil {
		return nil, err
	}

	return &certRes{
		RawCert: certPem,
		Cert:    template,
		RawKey:  keyPem,
		Key:     privateKey,
	}, nil
}

// EncodeKeyUsage encodes the key usage (See https://github.com/golang/go/issues/56866)
func EncodeKeyUsage(keyUsage x509.KeyUsage) []string {
	// Encode the key usage
	usage := []string{}

	if keyUsage&x509.KeyUsageDigitalSignature == x509.KeyUsageDigitalSignature {
		usage = append(usage, "Digital Signature")
	}

	if keyUsage&x509.KeyUsageContentCommitment == x509.KeyUsageContentCommitment {
		usage = append(usage, "Content Commitment")
	}

	if keyUsage&x509.KeyUsageKeyEncipherment == x509.KeyUsageKeyEncipherment {
		usage = append(usage, "Key Encipherment")
	}

	if keyUsage&x509.KeyUsageDataEncipherment == x509.KeyUsageDataEncipherment {
		usage = append(usage, "Data Encipherment")
	}

	if keyUsage&x509.KeyUsageKeyAgreement == x509.KeyUsageKeyAgreement {
		usage = append(usage, "Key Agreement")
	}

	if keyUsage&x509.KeyUsageCertSign == x509.KeyUsageCertSign {
		usage = append(usage, "Certificate Signing")
	}

	if keyUsage&x509.KeyUsageCRLSign == x509.KeyUsageCRLSign {
		usage = append(usage, "CRL Signing")
	}

	if keyUsage&x509.KeyUsageEncipherOnly == x509.KeyUsageEncipherOnly {
		usage = append(usage, "Encipher Only")
	}

	if keyUsage&x509.KeyUsageDecipherOnly == x509.KeyUsageDecipherOnly {
		usage = append(usage, "Decipher Only")
	}

	return usage
}

// EncodeExtKeyUsage encodes the extended key usage (See https://github.com/golang/go/issues/56866)
func EncodeExtKeyUsage(extKeyUsages []x509.ExtKeyUsage) []string {
	// Encode the extended key usage
	usage := []string{}

	for _, extKeyUsage := range extKeyUsages {
		switch extKeyUsage {
		case x509.ExtKeyUsageAny:
			usage = append(usage, "Any")
		case x509.ExtKeyUsageServerAuth:
			usage = append(usage, "Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			usage = append(usage, "Client Authentication")
		case x509.ExtKeyUsageCodeSigning:
			usage = append(usage, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			usage = append(usage, "Email Protection")
		case x509.ExtKeyUsageIPSECEndSystem:
			usage = append(usage, "IPSEC End System")
		case x509.ExtKeyUsageIPSECTunnel:
			usage = append(usage, "IPSEC Tunnel")
		case x509.ExtKeyUsageIPSECUser:
			usage = append(usage, "IPSEC User")
		case x509.ExtKeyUsageTimeStamping:
			usage = append(usage, "Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			usage = append(usage, "OCSP Signing")
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			usage = append(usage, "Microsoft Server Gated Crypto")
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			usage = append(usage, "Netscape Server Gated Crypto")
		}
	}

	return usage
}

// InitInternalServerPki initializes the internal server PKI
func InitInternalServerPki(serverCommonName string, serverDnsSans []string, serverIpSans []net.IP, config InternalServerConfig, configDir string, mode common.SafeOpenMode) error {
	// Initialize the root keypair
	rootRes, err := generateCert(certReq{
		Subject: pkix.Name{
			CommonName: "PAM OAuth Root",
		},
		Root:        true,
		ParentCert:  nil,
		ParentKey:   nil,
		KeyUsage:    0,
		ExtKeyUsage: nil,
	})

	if err != nil {
		return err
	}

	err = common.SafeCreate(config.RootTlsCertPath, configDir, rootRes.RawCert, common.PROTECTED_FILE_MODE, common.PROTECTED_FOLDER_MODE, mode)

	if err != nil {
		return err
	}

	err = common.SafeCreate(config.RootTlsKeyPath, configDir, rootRes.RawKey, common.PROTECTED_FILE_MODE, common.PROTECTED_FOLDER_MODE, mode)

	if err != nil {
		return err
	}

	// Initialize the internal server keypair using the root keypair as the root
	serverRes, err := generateCert(certReq{
		Subject: pkix.Name{
			CommonName: serverCommonName,
		},
		DnsSans:     serverDnsSans,
		IpSans:      serverIpSans,
		Root:        false,
		ParentCert:  rootRes.Cert,
		ParentKey:   rootRes.Key,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})

	if err != nil {
		return err
	}

	err = common.SafeCreate(config.ServerTlsCertPath, configDir, serverRes.RawCert, common.PROTECTED_FILE_MODE, common.PROTECTED_FOLDER_MODE, mode)

	if err != nil {
		return err
	}

	err = common.SafeCreate(config.ServerTlsKeyPath, configDir, serverRes.RawKey, common.PROTECTED_FILE_MODE, common.PROTECTED_FOLDER_MODE, mode)

	if err != nil {
		return err
	}

	return nil
}

// InitInternalServerClient initializes the internal server client certificate
func InitInternalServerClient(commonName string, dnsSans []string, ipSans []net.IP, config InternalServerConfig) (*certRes, error) {
	if config.RootTlsCert == nil {
		return nil, errors.New("root TLS certificate is required")
	}

	// Initialize the clientRes keypair using the client root keypair as the root
	res, err := generateCert(certReq{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DnsSans:     dnsSans,
		IpSans:      ipSans,
		Root:        false,
		ParentCert:  config.RootTlsCert.Leaf,
		ParentKey:   config.RootTlsCert.PrivateKey.(*ecdsa.PrivateKey),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})

	if err != nil {
		return nil, err
	}

	return res, nil
}
