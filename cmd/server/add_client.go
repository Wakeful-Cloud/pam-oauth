package main

import (
	"errors"
	"net"
	"os"

	"github.com/drewstinnett/gout/v2"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"github.com/wakeful-cloud/pam-oauth/internal/common"
	"github.com/wakeful-cloud/pam-oauth/internal/server"
)

// Flags
var addClientCommonName string
var addClientDnsSans []string
var addClientIpSans []string
var addClientClientCertPath string
var addClientClientKeyPath string

// addClientCmd is the add client command
var addClientCmd = &cobra.Command{
	Use:     "add",
	Aliases: []string{"create"},
	Short:   "Add a new client",
	RunE: func(cmd *cobra.Command, args []string) error {
		if config.InternalServerConfig.ServerTlsKeypair == nil {
			return errors.New("internal server TLS certificate is required")
		}

		// Parse IP SANs
		ipSans := lo.Map(addClientIpSans, func(ip string, _ int) net.IP {
			return net.ParseIP(ip)
		})

		// Initialize the client certificate
		res, err := server.InitInternalServerClient(addClientCommonName, addClientDnsSans, ipSans, config.InternalServerConfig)

		if err != nil {
			return err
		}

		// Add the client to the allow list
		err = config.InternalServerConfig.ClientAllowList.Add(res.Cert)

		if err != nil {
			return err
		}

		err = server.SaveCertificateAllowList(config.InternalServerConfig.ClientAllowList, config.InternalServerConfig.ClientAllowListPath, configDir, common.SAFE_OPEN_MODE_TRUNCATE)

		if err != nil {
			return err
		}

		// Encode the server certificate
		serverCertPem, err := common.EncodeCert(config.InternalServerConfig.ServerTlsKeypair.Leaf.Raw)

		if err != nil {
			return err
		}

		// Get the current working directory
		cwd, err := os.Getwd()

		if err != nil {
			return err
		}

		// Save the client certificate and key
		if addClientClientCertPath != "stdout" {
			err = common.SafeCreate(addClientClientCertPath, cwd, res.RawCert, common.PROTECTED_FILE_MODE, common.PROTECTED_FOLDER_MODE, common.SAFE_OPEN_MODE_EXCL)

			if err != nil {
				return err
			}
		}

		if addClientClientKeyPath != "stdout" {
			err = common.SafeCreate(addClientClientKeyPath, cwd, res.RawKey, common.PROTECTED_FILE_MODE, common.PROTECTED_FOLDER_MODE, common.SAFE_OPEN_MODE_EXCL)

			if err != nil {
				return err
			}
		}

		// Print
		err = gout.Print(map[string]any{
			"client_certificate": string(res.RawCert),
			"client_key":         string(res.RawKey),
			"server_certificate": string(serverCertPem),
		})

		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	// Register the command
	clientCmd.AddCommand(addClientCmd)

	// Register the flags
	addClientCmd.Flags().StringVar(&addClientCommonName, "client-common-name", "", "Client Common Name (CN)")
	addClientCmd.Flags().StringSliceVar(&addClientDnsSans, "client-dns-san", []string{}, "Client DNS Subject Alternative Name (SAN)")
	addClientCmd.Flags().StringSliceVar(&addClientIpSans, "client-ip-san", []string{}, "Client IP Subject Alternative Name (SAN)")
	addClientCmd.Flags().StringVar(&addClientClientCertPath, "client-cert", "stdout", "Client certificate path")
	addClientCmd.Flags().StringVar(&addClientClientKeyPath, "client-key", "stdout", "Client key path")

	// Mark the flags as required
	err := addClientCmd.MarkFlagRequired("client-common-name")

	if err != nil {
		panic(err)
	}
}
