package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"

	"github.com/spf13/cobra"
	"github.com/wakeful-cloud/pam-oauth/internal/common"
	"github.com/wakeful-cloud/pam-oauth/internal/server"
)

// serveCmd is the server command
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the server",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Initialize the logger
		cleanup, err := common.InitLogger(config.Log.Level, config.Log.Output, config.Log.File, configDir)

		if err != nil {
			panic(err)
		}

		defer cleanup()

		// Initialize the challenges
		challenges, err := server.NewChallengeManager(config)

		if err != nil {
			// Log
			slog.Error("failed to initialize challenges",
				slog.Any("error", err),
			)

			return err
		}

		// Initialize the Echo instance
		echo, err := server.InitEcho(config, challenges)

		if err != nil {
			// Log
			slog.Error("failed to initialize echo",
				slog.Any("error", err),
			)

			return err
		}

		// Initialize the OAuth server
		shutdownOauthServer, err := server.InitOAuthServer(config.OAuthServer, echo)

		if err != nil {
			// Log
			slog.Error("failed to initialize oauth server",
				slog.Any("error", err),
			)

			return err
		}

		// Initialize the internal server
		shutdownInternalServer, err := server.InitInternalServer(config.InternalServerConfig, challenges)

		if err != nil {
			// Log
			slog.Error("failed to initialize internal server",
				slog.Any("error", err),
			)

			return err
		}

		// Listen for interrupt
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()

		// Wait for interrupt
		<-ctx.Done()

		// Shutdown the servers
		err = shutdownInternalServer()

		if err != nil {
			// Log
			slog.Error("failed to shutdown internal server",
				slog.Any("error", err),
			)

			return err
		}

		err = shutdownOauthServer()

		if err != nil {
			// Log
			slog.Error("failed to shutdown oauth server",
				slog.Any("error", err),
			)

			return err
		}

		return nil
	},
}

func init() {
	// Register the command
	rootCmd.AddCommand(serveCmd)
}
