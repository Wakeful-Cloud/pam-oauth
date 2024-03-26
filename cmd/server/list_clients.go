package main

import (
	"crypto/x509"
	"encoding/hex"

	"github.com/drewstinnett/gout/v2"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/wakeful-cloud/pam-oauth/internal/server"
)

// listClientCmd is the list clients command
var listClientCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List clients",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Print the clients
		err := gout.Print(lo.Map(config.InternalServerConfig.ClientAllowList.GetEntries(), func(entry *x509.Certificate, _ int) map[string]any {
			return map[string]any{
				"subject":             entry.Subject.String(),
				"issuer":              entry.Issuer.String(),
				"serial":              entry.SerialNumber.String(),
				"signature":           hex.EncodeToString(entry.Signature),
				"signature_algorithm": entry.SignatureAlgorithm.String(),
				"valid_from":          entry.NotBefore.String(),
				"valid_to":            entry.NotAfter.String(),
				"key_usage":           server.EncodeKeyUsage(entry.KeyUsage),
				"ext_key_usage":       server.EncodeExtKeyUsage(entry.ExtKeyUsage),
			}
		}))

		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	// Register the command
	clientCmd.AddCommand(listClientCmd)
}
