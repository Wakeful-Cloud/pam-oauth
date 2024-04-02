package main

import (
	"net"

	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/wakeful-cloud/pam-oauth/internal/common"
	"github.com/wakeful-cloud/pam-oauth/internal/server"
)

// Flags
var initializeOverwrite bool
var initializeConfig bool
var initializeInternalServerPki bool
var initializeServerCommonName string
var initializeServerDnsSans []string
var initializeServerIpSans []string

// initializeCmd is the initialize command
var initializeCmd = &cobra.Command{
	Use:     "initialize",
	Aliases: []string{"init"},
	Short:   "Initialize the server",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Get the mode
		openMode := lo.Ternary(initializeOverwrite, common.SAFE_OPEN_MODE_TRUNCATE, common.SAFE_OPEN_MODE_EXCL)

		// Initialize the config
		if initializeConfig {
			err := server.SaveConfig(config, configPath, configDir, openMode)

			if err != nil {
				return err
			}
		}

		// Initialize the internal server PKI1
		if initializeInternalServerPki {
			// Add the server common name to the DNS SANs if not already present
			if !lo.Contains(initializeServerDnsSans, initializeServerCommonName) {
				initializeServerDnsSans = append(initializeServerDnsSans, initializeServerCommonName)
			}

			// Parse IP SANs
			ipSans := lo.Map(initializeServerIpSans, func(ip string, _ int) net.IP {
				return net.ParseIP(ip)
			})

			err := server.InitInternalServerPki(addClientCommonName, initializeServerDnsSans, ipSans, config.InternalServerConfig, configDir, openMode)

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
	initializeCmd.Flags().BoolVar(&initializeInternalServerPki, "initialize-server-pki", true, "Initialize the internal server PKI")
	initializeCmd.Flags().StringVar(&initializeServerCommonName, "server-common-name", "localhost", "Internal server common name")
	initializeCmd.Flags().StringSliceVar(&initializeServerDnsSans, "server-dns-san", []string{"localhost"}, "Internal server DNS Subject Alternative Name (SAN) (Note that the common name is automatically added to the DNS SANs)")
	initializeCmd.Flags().StringSliceVar(&initializeServerIpSans, "server-ip-san", []string{"127.0.0.1", "::1"}, "Internal server IP Subject Alternative Name (SAN)")
}
