package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/wakeful-cloud/pam-oauth/internal/client"
	"github.com/wakeful-cloud/pam-oauth/internal/common"
)

// config is the global configuration
var config client.Config

// Flags
var configPath string
var configDir string

// rootCmd is the base command
var rootCmd = &cobra.Command{
	Use:          "pam-oauth-login",
	Short:        "PAM OAuth login shell",
	SilenceUsage: true,
	CompletionOptions: cobra.CompletionOptions{
		HiddenDefaultCmd: true,
	},
	Version: common.About,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Get self
		self, err := os.Executable()

		if err != nil {
			return err
		}

		// Get self information
		info, err := os.Stat(self)

		if err != nil {
			return err
		}

		// Ensure setuid/setuid bit is set
		mode := info.Mode()
		if mode&os.ModeSetuid == 0 || mode&os.ModeSetgid == 0 {
			return fmt.Errorf("setuid and/or setgid bit not set")
		}

		// Ensure the file is owned by root
		if info.Sys().(*syscall.Stat_t).Uid != 0 || info.Sys().(*syscall.Stat_t).Gid != 0 {
			return fmt.Errorf("file not owned by root user and/or group")
		}

		// Ensure the file is not writable by others
		perm := mode.Perm()
		if perm&0o022 != 0 {
			return fmt.Errorf("file is writable by other groups or users")
		}

		// Ensure running as root (probably redundant, but just in case)
		if syscall.Geteuid() != 0 {
			return fmt.Errorf("not running as root")
		}

		// Get information from the environment
		configPath, err = client.GetConfigPath()

		if err != nil {
			return err
		}

		challengeId, err := client.GetChallengeID()

		if err != nil {
			return err
		}

		// Make the config path absolute
		if !filepath.IsAbs(configPath) {
			var err error
			configPath, err = filepath.Abs(configPath)

			if err != nil {
				return err
			}

		}

		// Clean the config path
		configPath = filepath.Clean(configPath)

		// Get the config directory
		configDir = filepath.Dir(configPath)

		// Load the config
		config, err = client.LoadConfig(configPath, configDir)

		if err != nil {
			return err
		}

		// Initialize the logger
		cleanup, err := common.InitLogger(config.Log.Level, config.Log.Output, config.Log.File, configDir)

		if err != nil {
			return err
		}

		defer cleanup()

		// Initialize the client
		internalClient, err := client.NewInternalClient(config.InternalClientConfig)

		if err != nil {
			// Log
			slog.Error("failed to initialize internal client",
				slog.Any("error", err),
			)

			return err
		}

		// Get the challenge info
		username, challengeEnv, err := internalClient.GetChallengeInfo(challengeId)

		if err != nil {
			// Log
			slog.Error("failed to get challenge info",
				slog.String("challenge id", challengeId),
				slog.Any("error", err),
			)

			return err
		}

		// Update the environment
		if challengeEnv == nil {
			challengeEnv = map[string]string{}
		}

		challengeEnv[client.PAM_OAUTH_USERNAME] = username

		// Run the command
		stdout, stderr, err := client.EvaluateShellScript(config.CreateUserCommand, 5*time.Second, challengeEnv)

		if err != nil {
			// Log
			slog.Error("failed to run user creation command",
				slog.String("command", config.CreateUserCommand),
				slog.Any("environment", challengeEnv),
				slog.String("stdout", stdout),
				slog.String("stderr", stderr),
				slog.Any("error", err),
			)

			return err
		}

		// Get the user
		user, err := client.GetPwnam(username)

		if err != nil {
			// Log
			slog.Error("failed to get user",
				slog.String("username", username),
				slog.Any("error", err),
			)

			return err
		}

		// Switch to the user
		err = client.SwitchUser(user)

		if err != nil {
			// Log
			slog.Error("failed to switch to the user",
				slog.String("username", username),
				slog.Any("user", user),
				slog.Any("error", err),
			)

			return err
		}

		return fmt.Errorf("failed to switch to the user's login shell")
	},
}

func main() {
	// Execute the root command
	err := rootCmd.Execute()

	if err != nil {
		os.Exit(1)
	}
}
