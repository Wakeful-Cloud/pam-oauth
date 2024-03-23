package main

import (
	"github.com/spf13/cobra"
)

// clientCmd is the client parent command
var clientCmd = &cobra.Command{
	Use:     "client",
	Short:   "Client commands",
	Aliases: []string{"clients"},
}

func init() {
	// Register the command
	rootCmd.AddCommand(clientCmd)
}
