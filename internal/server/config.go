package server

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/hashicorp/go-version"
	"github.com/mcuadros/go-defaults"
	"github.com/pelletier/go-toml/v2"
	"github.com/samber/lo"
	"github.com/wakeful-cloud/pam-oauth/internal/common"
)

// InternalServerConfig is the internal server configuration
type InternalServerConfig struct {
	Address             string `toml:"address" comment:"The address to listen on for the internal server" default:"127.0.0.1"`
	Port                uint16 `toml:"port" comment:"The port to listen on for the internal server" default:"8081"`
	ClientAllowListPath string `toml:"client_allow_list" comment:"The path to the client TLS certificate allow list file" default:"./internal-client-allow-list.json"`
	RootTlsCertPath     string `toml:"root_cert" comment:"The path to the root TLS certificate file (for client verification)" default:"./internal-root.crt"`
	RootTlsKeyPath      string `toml:"root_key" comment:"The path to the root TLS key file" default:"./internal-root.key"`
	ServerTlsCertPath   string `toml:"server_cert" comment:"The path to the server TLS certificate file" default:"./internal-server.crt"`
	ServerTlsKeyPath    string `toml:"server_key" comment:"The path to the server TLS key file" default:"./internal-server.key"`
	Callback            string `toml:"callback,multiline" comment:"The expr-language callback expression (See the README.md for documentation)" default:"{\n  ok: false,\n  message: \"Warning: callback expression not set!\"\n}\n"`
	Timeout             int    `toml:"timeout" comment:"The challenge timeout (in seconds)" default:"300"`

	// The client certificate allow list
	ClientAllowList certificateAllowList `toml:"-"`

	// The root TLS keypair
	RootTlsCert *tls.Certificate `toml:"-"`

	// The interal server TLS kepair
	ServerTlsKeypair *tls.Certificate `toml:"-"`
}

// LogConfig is the logging configuration
type LogConfig struct {
	File   string           `toml:"file" comment:"Log file (if output is file)" default:"/var/log/pam-oauth-server.log"`
	Level  common.LogLevel  `toml:"level" comment:"Log level (One of debug, info, warn, or error)" default:"info"`
	Output common.LogOutput `toml:"output" comment:"Log output (One of file, stdout, or stderr)" default:"stderr"`
}

// OAuthClientConfig is the OAuth client configuration
type OAuthClientConfig struct {
	ClientID     string   `toml:"client_id" comment:"The OAuth client ID"`
	ClientSecret string   `toml:"client_secret" comment:"The OAuth client secret"`
	Scopes       []string `toml:"scopes" comment:"The OAuth scopes (openid scope is required if oidc_url is set)" default:"[openid,profile,email]"`
	OidcUrl      string   `toml:"oidc_url" comment:"The OIDC auto-discovery URL (Without the /.well-known/openid-configuration suffix; mutually exclusive with auth_url and token_url)"`
	AuthURL      string   `toml:"auth_url" comment:"The OAuth endpoint auth URL (Mutually exclusive with oidc_url)"`
	TokenURL     string   `toml:"token_url" comment:"The OAuth endpoint token URL (Mutually exclusive with oidc_url)"`
}

// OAuthServerConfig is the OAuth callback server configuration
type OAuthServerConfig struct {
	Address           string `toml:"address" comment:"The address to listen on for the OAuth callback server" default:"0.0.0.0"`
	Port              uint16 `toml:"port" comment:"The port to listen on for the OAuth callback server" default:"8080"`
	ServerTlsAuto     bool   `toml:"tls_auto" comment:"Automatically enable TLS via LetsEncrypt" default:"false"`
	ServerTlsAutoPath string `toml:"tls_auto_path" comment:"The path to the automatic TLS cache directory" default:"./letsencrypt"`
	ServerTlsCertPath string `toml:"tls_cert" comment:"The path to the server TLS certificate file"`
	ServerTlsKeyPath  string `toml:"tls_key" comment:"The path to the server TLS key file"`
	ExternalBaseUrl   string `toml:"external_base_url" comment:"The external base URL for the OAuth callback server" default:"http://localhost:8080"`

	// The TLS certificate and key
	ServerTlsKeypair *tls.Certificate `toml:"-"`
}

// Config is the global server configuration
type Config struct {
	Version              *version.Version     `toml:"version,omitempty" comment:"The configuration version (DO NOT CHANGE)"`
	InternalServerConfig InternalServerConfig `toml:"internal_server" comment:"Internal server configuration"`
	Log                  LogConfig            `toml:"log" comment:"Logging configuration"`
	OAuthClient          OAuthClientConfig    `toml:"oauth_client" comment:"OAuth client configuration"`
	OAuthServer          OAuthServerConfig    `toml:"oauth_server" comment:"OAuth callback server configuration"`
}

// SaveConfig saves a configuration file
func SaveConfig(config Config, name string, relative string, mode common.SafeOpenMode) error {
	// Marshal the configuration
	raw, err := toml.Marshal(config)

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

// LoadConfig loads a configuration file
func LoadConfig(name string, relative string) (Config, error) {
	// Add defaults
	var config Config
	defaults.SetDefaults(&config)

	if config.Version == nil {
		config.Version = common.Version
	}

	// Read the config file
	rawConfig, err := common.SafeRead(name, relative)

	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Config{}, err
	} else if err == nil {
		// Unmarshal the file
		err := toml.Unmarshal(rawConfig, &config)

		if err != nil {
			return Config{}, err
		}
	}

	// Check the version of the configuration
	if !common.VersionConstraint.Check(config.Version) {
		return Config{}, fmt.Errorf("unsupported configuration version \"%s\"", config.Version)
	}

	// Validate the configuration
	parsedAddress := net.ParseIP(config.OAuthServer.Address)
	if len(parsedAddress) == 0 {
		return Config{}, fmt.Errorf("invalid address \"%s\"", config.OAuthServer.Address)
	}

	if config.OAuthServer.Port == 0 {
		return Config{}, errors.New("invalid port 0")
	}

	if (config.OAuthServer.ServerTlsAuto && config.OAuthServer.ServerTlsAutoPath != "") && (config.OAuthServer.ServerTlsCertPath != "" || config.OAuthServer.ServerTlsKeyPath != "") {
		return Config{}, errors.New("tls_auto/tls_auto_path and tls_cert/tls_key options are mutually exclusive")
	}

	if config.InternalServerConfig.Port == config.OAuthServer.Port {
		return Config{}, errors.New("auth server and OAuth server ports cannot be the same")
	}

	if config.OAuthClient.OidcUrl != "" && !lo.Contains(config.OAuthClient.Scopes, "openid") {
		return Config{}, errors.New("openid scope is required if oidc_url is set")
	}

	if config.OAuthClient.OidcUrl != "" && (config.OAuthClient.AuthURL != "" || config.OAuthClient.TokenURL != "") {
		return Config{}, errors.New("oidc_url and auth_url/token_url options are mutually exclusive")
	}

	// Ensure protected files
	err = common.EnsureProtectedFile(config.InternalServerConfig.ClientAllowListPath, relative)

	if err != nil {
		return Config{}, err
	}

	err = common.EnsureProtectedFile(config.InternalServerConfig.RootTlsCertPath, relative)

	if err != nil {
		return Config{}, err
	}

	err = common.EnsureProtectedFile(config.InternalServerConfig.RootTlsKeyPath, relative)

	if err != nil {
		return Config{}, err
	}

	err = common.EnsureProtectedFile(config.InternalServerConfig.ServerTlsCertPath, relative)

	if err != nil {
		return Config{}, err
	}

	err = common.EnsureProtectedFile(config.InternalServerConfig.ServerTlsKeyPath, relative)

	if err != nil {
		return Config{}, err
	}

	if config.OAuthServer.ServerTlsCertPath != "" {
		err = common.EnsureProtectedFile(config.OAuthServer.ServerTlsCertPath, relative)

		if err != nil {
			return Config{}, err
		}
	}

	if config.OAuthServer.ServerTlsKeyPath != "" {
		err = common.EnsureProtectedFile(config.OAuthServer.ServerTlsKeyPath, relative)

		if err != nil {
			return Config{}, err
		}
	}

	// Read files
	rawInternalRootCert, err := common.SafeRead(config.InternalServerConfig.RootTlsCertPath, relative)

	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Config{}, err
	}

	rawInternalRootKey, err := common.SafeRead(config.InternalServerConfig.RootTlsKeyPath, relative)

	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Config{}, err
	}

	rawInternalServerTlsCert, err := common.SafeRead(config.InternalServerConfig.ServerTlsCertPath, relative)

	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Config{}, err
	}

	rawInternalServerTlsKey, err := common.SafeRead(config.InternalServerConfig.ServerTlsKeyPath, relative)

	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Config{}, err
	}

	if config.OAuthServer.ServerTlsCertPath != "" && config.OAuthServer.ServerTlsKeyPath != "" {
		rawOauthTlsCert, err := common.SafeRead(config.OAuthServer.ServerTlsCertPath, relative)

		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return Config{}, err
		}

		rawOauthTlsKey, err := common.SafeRead(config.OAuthServer.ServerTlsKeyPath, relative)

		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return Config{}, err
		}

		keypair, err := tls.X509KeyPair(rawOauthTlsCert, rawOauthTlsKey)

		if err != nil {
			return Config{}, err
		}

		config.OAuthServer.ServerTlsKeypair = &keypair
	}

	// Parse and decode the files
	if rawInternalRootCert != nil && rawInternalRootKey != nil {
		keypair, err := tls.X509KeyPair(rawInternalRootCert, rawInternalRootKey)

		if err != nil {
			return Config{}, err
		}

		config.InternalServerConfig.RootTlsCert = &keypair

		cert, err := x509.ParseCertificate(keypair.Certificate[0])

		if err != nil {
			return Config{}, err
		}

		config.InternalServerConfig.RootTlsCert.Leaf = cert
	}

	if rawInternalServerTlsCert != nil && rawInternalServerTlsKey != nil {
		keypair, err := tls.X509KeyPair(rawInternalServerTlsCert, rawInternalServerTlsKey)

		if err != nil {
			return Config{}, err
		}

		config.InternalServerConfig.ServerTlsKeypair = &keypair

		cert, err := x509.ParseCertificate(keypair.Certificate[0])

		if err != nil {
			return Config{}, err
		}

		config.InternalServerConfig.ServerTlsKeypair.Leaf = cert
	}

	// Load the certificate allow list
	if config.InternalServerConfig.ClientAllowListPath != "" {
		config.InternalServerConfig.ClientAllowList, err = LoadCertificateAllowList(config.InternalServerConfig.ClientAllowListPath, relative)

		if errors.Is(err, os.ErrNotExist) {
			config.InternalServerConfig.ClientAllowList = newCertificateAllowList()
		} else if err != nil {
			return Config{}, err
		}
	}

	return config, nil
}
