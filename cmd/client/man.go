//go:build man

package main

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"github.com/wakeful-cloud/pam-oauth/internal/common"
)

// Flags
var outputDir string

// manCmd is the man page generator command
var manCmd = &cobra.Command{
	Use:    "man",
	Short:  "Generate the man pages",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Get the current working directory
		cwd, err := os.Getwd()

		if err != nil {
			return err
		}

		// Make the parent directories
		err = common.MakeDirs(outputDir, cwd, common.PROTECTED_FOLDER_MODE)

		if err != nil {
			return err
		}

		// Generate the man page
		err = doc.GenManTree(rootCmd, nil, outputDir)

		if err != nil {
			return err
		}

		return nil
	},
}

func init() {
	// Register the command
	rootCmd.AddCommand(manCmd)

	// Register the flags
	manCmd.Flags().StringVar(&outputDir, "output", "man", "The output directory for the man pages")
}
