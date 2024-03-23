package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// PamExitCode is the exit code returned by a pam_exec binary
type PamExitCode int

const (
	// Successful function return
	PAM_SUCCESS PamExitCode = 0

	// dlopen() failure when dynamically loading a service module
	PAM_OPEN_ERR PamExitCode = 1

	// Symbol not found
	PAM_SYMBOL_ERR PamExitCode = 2

	// Error in service module
	PAM_SERVICE_ERR PamExitCode = 3

	// System error
	PAM_SYSTEM_ERR PamExitCode = 4

	// Memory buffer error
	PAM_BUF_ERR PamExitCode = 5

	// Permission denied
	PAM_PERM_DENIED PamExitCode = 6

	// Authentication failure
	PAM_AUTH_ERR PamExitCode = 7

	// Can not access authentication data due to insufficient credentials
	PAM_CRED_INSUFFICIENT PamExitCode = 8

	// Underlying authentication service can not retrieve authentication information
	PAM_AUTHINFO_UNAVAIL PamExitCode = 9

	// User not known to the underlying authentication module
	PAM_USER_UNKNOWN PamExitCode = 10

	// An authentication service has maintained a retry count which has been reached. No further retries should be attempted
	PAM_MAXTRIES PamExitCode = 11

	// New authentication token required. This is normally returned if the machine security policies require that the password should be changed beccause the password is NULL or it has aged
	PAM_NEW_AUTHTOK_REQD PamExitCode = 12

	// User account has expired
	PAM_ACCT_EXPIRED PamExitCode = 13

	// Can not make/remove an entry for the specified session
	PAM_SESSION_ERR PamExitCode = 14

	// Underlying authentication service can not retrieve user credentials unavailable
	PAM_CRED_UNAVAIL PamExitCode = 15

	// User credentials expired
	PAM_CRED_EXPIRED PamExitCode = 16

	// Failure setting user credentials
	PAM_CRED_ERR PamExitCode = 17

	// No module specific data is present
	PAM_NO_MODULE_DATA PamExitCode = 18

	// Conversation error
	PAM_CONV_ERR PamExitCode = 19

	// Authentication token manipulation error
	PAM_AUTHTOK_ERR PamExitCode = 20

	// Authentication information cannot be recovered
	PAM_AUTHTOK_RECOVERY_ERR PamExitCode = 21

	// Authentication token lock busy
	PAM_AUTHTOK_LOCK_BUSY PamExitCode = 22

	// Authentication token aging error
	PAM_AUTHTOK_DISABLE_AGING PamExitCode = 23

	// Preliminary check by password service
	PAM_TRY_AGAIN PamExitCode = 24

	// Ignore underlying account module regardless of whether the control flag is required, optional, or sufficient
	PAM_IGNORE PamExitCode = 25

	// Critical error value (?module fail now request)
	PAM_ABORT PamExitCode = 26

	// User's authentication token has expired
	PAM_AUTHTOK_EXPIRED PamExitCode = 27

	// Module is not known
	PAM_MODULE_UNKNOWN PamExitCode = 28

	// Bad item passed to pam_*_item()
	PAM_BAD_ITEM PamExitCode = 29

	// Conversation function is event driven and data is not available yet
	PAM_CONV_AGAIN PamExitCode = 30

	// Please call this function again to complete authentication stack. Before calling again, verify that conversation is completed
	PAM_INCOMPLETE PamExitCode = 31
)

// PamErrorWithCode is an error with a PAM exit code
type PamErrorWithCode struct {
	code PamExitCode
	err  error
}

// NewPamErrorWithCode returns a new PamErrorWithCode
func NewPamErrorWithCode(code PamExitCode, err error) *PamErrorWithCode {
	return &PamErrorWithCode{
		code: code,
		err:  err,
	}
}

// Code returns the PAM exit code
func (err *PamErrorWithCode) Code() PamExitCode {
	return err.code
}

// Error returns the error message
func (err *PamErrorWithCode) Error() string {
	return err.err.Error()
}

// Unwrap returns the underlying error
func (err *PamErrorWithCode) Unwrap() error {
	return err.err
}

// Passed from the PAM wrapper to the client
const (
	// PAM_REMOTE_HOST_KEY is the environment variable key for the remote host
	PAM_REMOTE_HOST_KEY = "PAM_RHOST"

	// PAM_REMOTE_USER_KEY is the environment variable key for the remote user
	PAM_REMOTE_USER_KEY = "PAM_RUSER"

	// PAM_SERVICE_KEY is the environment variable key for the service
	PAM_SERVICE_KEY = "PAM_SERVICE"

	// PAM_TTY_KEY is the environment variable key for the tty
	PAM_TTY_KEY = "PAM_TTY"

	// PAM_USERNAME_KEY is the environment variable key for the username
	PAM_USERNAME_KEY = "PAM_USER"

	// PAM_TYPE_KEY is the environment variable key for the service module type
	PAM_TYPE_KEY = "PAM_TYPE"
)

// Passed from the client to the create user command
const (
	// PAM_OAUTH_USERNAME is the environment variable key for the username
	PAM_OAUTH_USERNAME = "PAM_OAUTH_USERNAME"
)

// Passed from the client to the PAM wrapper to the login shell
const (
	// PAM_OAUTH_CONFIG is the environment variable key for the configuration path
	PAM_OAUTH_CONFIG = "PAM_OAUTH_CONFIG"

	// PAM_OAUTH_CHALLENGE_ID is the environment variable key for the challenge ID
	PAM_OAUTH_CHALLENGE_ID = "PAM_OAUTH_CHALLENGE_ID"
)

// PamSmType is the type of PAM service module type
type PamSmType string

const (
	// User authentication
	PAM_SM_AUTHENTICATE PamSmType = "pam_sm_authenticate"

	// Alter credentials
	// #nosec G101
	PAM_SM_SETCRED PamSmType = "pam_sm_setcred"

	// Account management
	PAM_SM_ACCT_MGMT PamSmType = "pam_sm_acct_mgmt"

	// Start session management
	PAM_SM_OPEN_SESSION PamSmType = "pam_sm_open_session"

	// Terminate session management
	PAM_SM_CLOSE_SESSION PamSmType = "pam_sm_close_session"

	// Alter the authentication token (password)
	PAM_SM_CHAUTHTOK PamSmType = "pam_sm_chauthtok"
)

var (
	// ErrPAMRemoteHostNotFound is returned when the PAM remote host is not found
	ErrPAMRemoteHostNotFound = errors.New("PAM remote host not found")

	// ErrPAMRemoteUserNotFound is returned when the PAM remote user is not found
	ErrPAMRemoteUserNotFound = errors.New("PAM remote user not found")

	// ErrPAMServiceNotFound is returned when the PAM service is not found
	ErrPAMServiceNotFound = errors.New("PAM service not found")

	// ErrPAMTTYNotFound is returned when the PAM TTY is not found
	ErrPAMTTYNotFound = errors.New("PAM TTY not found")

	// ErrPAMUsernameNotFound is returned when the PAM username is not found
	ErrPAMUsernameNotFound = errors.New("PAM username not found")

	// ErrPAMTypeNotFound is returned when the PAM type is not found
	ErrPAMTypeNotFound = errors.New("PAM type not found")

	// ErrPAMTypeInvalid is returned when the PAM type is invalid
	ErrPAMTypeInvalid = errors.New("PAM type invalid")

	// ErrPAMOAuthConfigNotFound is returned when the PAM OAuth config is not found
	ErrPAMOAuthConfigNotFound = errors.New("PAM OAuth config not found")

	// ErrPAMOAuthChallengeIDNotFound is returned when the PAM OAuth challenge ID is not found
	ErrPAMOAuthChallengeIDNotFound = errors.New("PAM OAuth challenge ID not found")
)

// GetRemoteHost returns the remote host from the environment
func GetRemoteHost() (string, error) {
	remoteHost, ok := os.LookupEnv(PAM_REMOTE_HOST_KEY)

	if !ok {
		return "", ErrPAMRemoteHostNotFound
	}

	return remoteHost, nil
}

// GetRemoteUser returns the remote user from the environment
func GetRemoteUser() (string, error) {
	remoteUser, ok := os.LookupEnv(PAM_REMOTE_USER_KEY)

	if !ok {
		return "", ErrPAMRemoteUserNotFound
	}

	return remoteUser, nil
}

// GetService returns the service from the environment
func GetService() (string, error) {
	service, ok := os.LookupEnv(PAM_SERVICE_KEY)

	if !ok {
		return "", ErrPAMServiceNotFound
	}

	return service, nil
}

// GetTTY returns the tty from the environment
func GetTTY() (string, error) {
	tty, ok := os.LookupEnv(PAM_TTY_KEY)

	if !ok {
		return "", ErrPAMTTYNotFound
	}

	return tty, nil
}

// GetUsername returns the username from the environment
func GetUsername() (string, error) {
	username, ok := os.LookupEnv(PAM_USERNAME_KEY)

	if !ok {
		return "", ErrPAMUsernameNotFound
	}

	return username, nil
}

// GetType returns the type from the environment
func GetType() (PamSmType, error) {
	raw, ok := os.LookupEnv(PAM_TYPE_KEY)

	if !ok {
		return "", ErrPAMTypeNotFound
	}

	switch PamSmType(raw) {
	case PAM_SM_AUTHENTICATE, PAM_SM_SETCRED, PAM_SM_ACCT_MGMT, PAM_SM_OPEN_SESSION, PAM_SM_CLOSE_SESSION, PAM_SM_CHAUTHTOK:
		return PamSmType(raw), nil
	default:
		return "", ErrPAMTypeInvalid
	}
}

// GetConfigPath returns the configuration path from the environment
func GetConfigPath() (string, error) {
	configPath := os.Getenv(PAM_OAUTH_CONFIG)

	if configPath == "" {
		return "", ErrPAMOAuthConfigNotFound
	}

	return configPath, nil
}

// GetChallengeID returns the challenge ID from the environment
func GetChallengeID() (string, error) {
	challengeID := os.Getenv(PAM_OAUTH_CHALLENGE_ID)

	if challengeID == "" {
		return "", ErrPAMOAuthChallengeIDNotFound
	}

	return challengeID, nil
}

// SetConfigPath sets the configuration path in the PAM module environment
func SetConfigPath(configPath string) error {
	// Encode the putenv message
	raw, err := json.Marshal(map[string]any{
		"type":  "putenv",
		"name":  PAM_OAUTH_CONFIG,
		"value": configPath,
	})

	if err != nil {
		return err
	}

	// Send the putenv message
	_, err = fmt.Printf("%s\n", raw)

	if err != nil {
		return err
	}

	return nil
}

// SetChallengeID sets the challenge ID in the PAM module environment
func SetChallengeID(challengeID string) error {
	// Encode the putenv message
	raw, err := json.Marshal(map[string]any{
		"type":  "putenv",
		"name":  PAM_OAUTH_CHALLENGE_ID,
		"value": challengeID,
	})

	if err != nil {
		return err
	}

	// Send the putenv message
	_, err = fmt.Printf("%s\n", raw)

	if err != nil {
		return err
	}

	return nil
}
