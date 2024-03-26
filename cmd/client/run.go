package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"
	"github.com/wakeful-cloud/pam-oauth/internal/client"
	"github.com/wakeful-cloud/pam-oauth/internal/common"
)

// errSkipMethod is returned when the authentication method is skipped
var errSkipMethod = client.NewPamErrorWithCode(client.PAM_AUTH_ERR, errors.New("skipping authentication method"))

// errAuthenticateTimeout is returned when the authentication times out
var errAuthenticateTimeout = client.NewPamErrorWithCode(client.PAM_AUTH_ERR, errors.New("authentication timed out"))

// runCmd is the run command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the module",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Initialize the logger
		cleanup, err := common.InitLogger(config.Log.Level, config.Log.Output, config.Log.File, configDir)

		if err != nil {
			return err
		}

		defer cleanup()

		// Get information from the environment
		smType, err := client.GetType()

		if err != nil {
			// Log
			slog.Error("failed to get type",
				slog.Any("error", err),
			)

			return err
		}

		username, err := client.GetUsername()

		if err != nil {
			// Log
			slog.Error("failed to get username",
				slog.Any("error", err),
			)

			return err
		}

		// Skip non-authentication requests
		if smType != client.PAM_SM_AUTHENTICATE {
			// Log
			slog.Info("skipping non-authentication request",
				slog.String("type", string(smType)),
			)

			return errSkipMethod
		}

		// Initialize the client
		internalClient, err := client.NewInternalClient(config.InternalClientConfig)

		if err != nil {
			// Log
			slog.Error("failed to initialize internal client",
				slog.Any("error", err),
			)

			return err
		}

		// Issue a challenge
		id, url, err := internalClient.IssueChallenge(username)

		if err != nil {
			// Log
			slog.Error("failed to issue challenge",
				slog.Any("error", err),
			)

			return err
		}

		// Format the message
		message, err := client.EvaluateTextTemplate(config.Prompt.Message, map[string]string{
			"Username": username,
			"Url":      url,
		})

		if err != nil {
			// Log
			slog.Error("failed to format prompt message",
				slog.Any("error", err),
			)

			return err
		}

		// Encode the prompt message
		raw, err := json.Marshal(map[string]any{
			"type":    "prompt",
			"style":   2,
			"message": message,
		})

		if err != nil {
			// Log
			slog.Error("failed to encode prompt message",
				slog.Any("error", err),
			)

			return err
		}

		// Send the prompt message
		fmt.Printf("%s\n", raw)

		// Read the verification code
		var code string
		_, err = fmt.Scanln(&code)

		if err != nil {
			// Log
			slog.Error("failed to scan input",
				slog.Any("error", err),
			)

			return err
		}

		// Validate the code
		if len(code) != common.VERIFICATION_CODE_LENGTH {
			// Log
			slog.Error("invalid verification code",
				slog.String("code", code),
			)

			return errSkipMethod
		}

		// Verify the challenge
		verified, err := internalClient.VerifyChallenge(id, code)

		if err != nil {
			// Log
			slog.Error("failed to verify code",
				slog.Any("error", err),
			)

			return err
		}

		if !verified {
			// Log
			slog.Info("challenge timed out or failed",
				slog.String("username", username),
			)

			return errAuthenticateTimeout
		}

		// Update the environment
		err = client.SetConfigPath(configPath)

		if err != nil {
			// Log
			slog.Error("failed to set config path",
				slog.Any("error", err),
			)

			return err
		}

		err = client.SetChallengeID(id)

		if err != nil {
			// Log
			slog.Error("failed to set challenge ID",
				slog.Any("error", err),
			)

			return err
		}

		// Log
		slog.Info("challenge verified",
			slog.String("username", username),
		)

		return nil
	},
}

func init() {
	// Register the command
	rootCmd.AddCommand(runCmd)
}
