package main

import (
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/wakeful-cloud/pam-oauth/internal/client"
	"github.com/wakeful-cloud/pam-oauth/internal/common"
)

// Flags
var initializeOverwrite bool
var initializeConfig bool

// initializeCmd is the initialize command
var initializeCmd = &cobra.Command{
	Use:     "initialize",
	Aliases: []string{"init"},
	Short:   "Initialize the client",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Get the mode
		openMode := lo.Ternary(initializeOverwrite, common.SAFE_OPEN_MODE_TRUNCATE, common.SAFE_OPEN_MODE_EXCL)

		// Initialize the config
		if initializeConfig {
			err := client.SaveConfig(config, configPath, configDir, openMode)

			if err != nil {
				return err
			}
		}

		return nil
	},
}

func init() {
	// Register the command
	rootCmd.AddCommand(initializeCmd)

	// Register the flags
	initializeCmd.Flags().BoolVar(&initializeOverwrite, "overwrite", false, "Overwrite existing files")
	initializeCmd.Flags().BoolVar(&initializeConfig, "initialize-config", true, "Initialize the configuration")
}
