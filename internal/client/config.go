package client

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"github.com/hashicorp/go-version"
	"github.com/mcuadros/go-defaults"
	"github.com/pelletier/go-toml/v2"
	"github.com/wakeful-cloud/pam-oauth/internal/common"
)

// InternalClientConfig is the internal server client configuration
type InternalClientConfig struct {
	Host              string `toml:"host" comment:"The host (address/domain) of the internal server" default:"127.0.0.1"`
	Port              uint16 `toml:"port" comment:"The port of the internal server" default:"8081"`
	ClientTlsCertPath string `toml:"client_cert" comment:"The path to the client TLS certificate file" default:"./internal-client.crt"`
	ClientTlsKeyPath  string `toml:"client_key" comment:"The path to the client TLS key file" default:"./internal-client.key"`
	ServerTlsCertPath string `toml:"server_cert" comment:"The path to the server TLS certificate file (for server verification)" default:"./internal-server.crt"`
	Timeout           int    `toml:"timeout" comment:"The challenge timeout (in seconds)" default:"300"`

	// The interal server client TLS kepair
	ClientTlsKeypair *tls.Certificate `toml:"-"`

	// The internal server TLS keypair
	ServerTlsCert *x509.Certificate `toml:"-"`
}

// LogConfig is the logging configuration
type LogConfig struct {
	File   string           `toml:"file" comment:"Log file (if output is file)" default:"/var/log/pam-oauth-client.log"`
	Level  common.LogLevel  `toml:"level" comment:"Log level (One of debug, info, warn, or error)" default:"info"`
	Output common.LogOutput `toml:"output" comment:"Log output (One of file, stdout, or stderr)" default:"stderr"`
}

// PromptConfig is the prompt configuration
type PromptConfig struct {
	Message string `toml:"message" comment:"The Go template representing the message to display to the user to make them authenticate (See the README.md for documentation)" default:"Please open {{ .Url }} in your browser to authenticate and enter the code you receive here or press enter without a code to skip this authentication method: "`
}

// Config is the global client configuration
type Config struct {
	Version              *version.Version     `toml:"version,omitempty" comment:"The configuration version (DO NOT CHANGE)"`
	CreateUserCommand    string               `toml:"create_user_command" comment:"The command to run to create a user the first time they authenticate (See the README.md for documentation)" default:"useradd --create-home --user-group --shell /bin/bash $PAM_OAUTH_USERNAME"`
	InternalClientConfig InternalClientConfig `toml:"internal_client" comment:"Internal server client configuration"`
	Log                  LogConfig            `toml:"log" comment:"Logging configuration"`
	Prompt               PromptConfig         `toml:"prompt" comment:"Prompt configuration"`
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
	if config.InternalClientConfig.Port == 0 {
		return Config{}, errors.New("invalid port 0")
	}

	// Ensure protected files
	err = common.EnsureProtectedFile(config.InternalClientConfig.ServerTlsCertPath, relative)

	if err != nil {
		return Config{}, err
	}

	err = common.EnsureProtectedFile(config.InternalClientConfig.ClientTlsCertPath, relative)

	if err != nil {
		return Config{}, err
	}

	err = common.EnsureProtectedFile(config.InternalClientConfig.ClientTlsKeyPath, relative)

	if err != nil {
		return Config{}, err
	}

	// Read files
	rawInternalServerCert, err := common.SafeRead(config.InternalClientConfig.ServerTlsCertPath, relative)

	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Config{}, err
	}

	rawInternalClientTlsCert, err := common.SafeRead(config.InternalClientConfig.ClientTlsCertPath, relative)

	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Config{}, err
	}

	rawInternalClientTlsKey, err := common.SafeRead(config.InternalClientConfig.ClientTlsKeyPath, relative)

	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Config{}, err
	}

	// Parse and decode the files
	if rawInternalServerCert != nil {
		block, err := common.DecodeCert(rawInternalServerCert)

		if err != nil {
			return Config{}, err
		}

		cert, err := x509.ParseCertificate(block.Bytes)

		if err != nil {
			return Config{}, err
		}

		config.InternalClientConfig.ServerTlsCert = cert
	}

	if rawInternalClientTlsCert != nil && rawInternalClientTlsKey != nil {
		keypair, err := tls.X509KeyPair(rawInternalClientTlsCert, rawInternalClientTlsKey)

		if err != nil {
			return Config{}, err
		}

		config.InternalClientConfig.ClientTlsKeypair = &keypair

		cert, err := x509.ParseCertificate(keypair.Certificate[0])

		if err != nil {
			return Config{}, err
		}

		config.InternalClientConfig.ClientTlsKeypair.Leaf = cert
	}

	return config, nil
}
