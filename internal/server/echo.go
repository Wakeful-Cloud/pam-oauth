package server

import (
	"log/slog"
	"net/http"

	_ "embed"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	slogecho "github.com/samber/slog-echo"
)

// InitEcho initializes a new Echo instance
func InitEcho(config Config, challengeManager *ChallengeManager) (*echo.Echo, error) {
	// Initialize Echo
	app := echo.New()

	// Register middleware
	app.Use(slogecho.New(slog.Default()))
	app.Use(middleware.BodyLimit("4M"))
	app.Use(middleware.Decompress())
	app.Use(middleware.RateLimiter(middleware.NewRateLimiterMemoryStore(10)))
	app.Use(middleware.Recover())
	app.Use(middleware.Secure())
	app.Use(middleware.Timeout())
	app.Use(middleware.AddTrailingSlash())
	app.Use(middleware.Gzip())
	app.Group("static").Use(middleware.StaticWithConfig(middleware.StaticConfig{
		Root:       "web/static",
		Filesystem: http.FS(staticFiles),
	}))

	// Register routes
	app.GET("/oauth/begin", func(ctx echo.Context) error {
		// Get the query parameters
		challengeId := ctx.QueryParam("challenge")

		if challengeId == "" {
			return ctx.String(http.StatusBadRequest, "challenge query parameter is required")
		}

		// Log
		slog.Debug("beginning OAuth flow",
			slog.String("challenge ID", challengeId),
		)

		// Generate the OAuth callback URL
		oAuthUrl, err := challengeManager.Step2(challengeId)

		if err != nil {
			return ctx.String(http.StatusBadRequest, err.Error())
		}

		// Redirect
		return ctx.Redirect(http.StatusFound, oAuthUrl)
	})

	app.GET("/oauth/end", func(ctx echo.Context) error {
		// Get the query parameters
		state := ctx.QueryParam("state")
		code := ctx.QueryParam("code")

		if state == "" {
			return ctx.String(http.StatusBadRequest, "state query parameter is required")
		}

		if code == "" {
			return ctx.String(http.StatusBadRequest, "code query parameter is required")
		}

		// Log
		slog.Debug("verifying challenge",
			slog.String("OAuth state", state),
			slog.String("OAuth code", code),
		)

		// Generate the verification code
		verificationCode, message, err := challengeManager.Step3(state, code)

		if err != nil {
			return ctx.String(http.StatusBadRequest, err.Error())
		}

		// Log
		slog.Debug("verification status",
			slog.String("OAuth state", state),
			slog.String("OAuth code", code),
			slog.String("verification code", verificationCode),
			slog.String("message", message),
		)

		// Execute the flow end page template
		err = renderFlowPage(ctx.Response().Writer, flowEndPageEnv{
			Message: message,
			Code:    verificationCode,
		})

		if err != nil {
			return ctx.String(http.StatusInternalServerError, err.Error())
		}

		return nil
	})

	return app, nil
}
