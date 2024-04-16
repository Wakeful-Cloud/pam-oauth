package main

import (
	"os"
	"path/filepath"

	goutbra "github.com/drewstinnett/gout-cobra"
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
	Use:          "pam-oauth-client",
	Short:        "PAM OAuth client",
	SilenceUsage: true,
	CompletionOptions: cobra.CompletionOptions{
		HiddenDefaultCmd: true,
	},
	Version: common.About,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
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
		var err error
		config, err = client.LoadConfig(configPath, configDir)

		if err != nil {
			return err
		}

		// Initialize goutbra
		err = goutbra.Cmd(cmd)

		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	// Register the flags
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "/etc/pam-oauth/client.toml", "config file")
	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	// Bind goutbra
	err := goutbra.Bind(rootCmd)

	if err != nil {
		panic(err)
	}
}

func main() {
	// Execute the root command
	err := rootCmd.Execute()

	if err != nil {
		exitCode, ok := err.(*client.PamErrorWithCode)

		if ok {
			os.Exit(int(exitCode.Code()))
		} else {
			os.Exit(int(client.PAM_SERVICE_ERR))
		}
	}
}
