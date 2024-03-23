package main

import (
	"crypto/x509"

	"github.com/spf13/cobra"
	"github.com/wakeful-cloud/pam-oauth/internal/common"
	"github.com/wakeful-cloud/pam-oauth/internal/server"
)

// Flags
var removeClientCommonName string

// removeClientCmd is the remove client command
var removeClientCmd = &cobra.Command{
	Use:     "remove",
	Aliases: []string{"delete", "rm"},
	Short:   "Remove an existing client",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Remove the client to the allow list
		err := config.InternalServerConfig.ClientAllowList.Remove(func(entry *x509.Certificate) (bool, error) {
			return entry.Subject.CommonName == removeClientCommonName, nil
		})

		if err != nil {
			return err
		}

		err = server.SaveCertificateAllowList(config.InternalServerConfig.ClientAllowList, config.InternalServerConfig.ClientAllowListPath, configDir, common.SAFE_OPEN_MODE_TRUNCATE)

		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	// Register the command
	clientCmd.AddCommand(removeClientCmd)

	// Register the flags
	removeClientCmd.Flags().StringVar(&removeClientCommonName, "common-name", "", "Client common name")

	// Mark the flags as required
	err := removeClientCmd.MarkFlagRequired("common-name")

	if err != nil {
		panic(err)
	}
}
