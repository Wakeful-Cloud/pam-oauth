package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// InitOAuthServer initializes a new HTTP server, returning a shutdown function and an error (if any)
func InitOAuthServer(config OAuthServerConfig, handler http.Handler) (func() error, error) {
	// Log
	slog.Info("starting OAuth server",
		slog.String("listening address", config.Address),
		slog.Int("listening port", int(config.Port)),
	)

	// Initialize the server
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", config.Address, config.Port),
		Handler:      handler,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  120 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion:               tls.VersionTLS13,
			PreferServerCipherSuites: true,
		},
	}

	// Start the server
	go func() {
		var err error

		if config.ServerTlsAuto {
			autoTLSManager := autocert.Manager{
				Cache:  autocert.DirCache(config.ServerTlsAutoPath),
				Prompt: autocert.AcceptTOS,
			}
			server.TLSConfig.GetCertificate = autoTLSManager.GetCertificate
			server.TLSConfig.NextProtos = []string{acme.ALPNProto}

			err = server.ListenAndServeTLS("", "")
		} else if config.ServerTlsKeypair != nil {
			server.TLSConfig.Certificates = append(server.TLSConfig.Certificates, *config.ServerTlsKeypair)

			err = server.ListenAndServeTLS("", "")
		} else {
			err = server.ListenAndServe()
		}

		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			// Log
			slog.Error("OAuth server error",
				slog.Any("error", err),
			)

			panic(err)
		}
	}()

	return func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		return server.Shutdown(ctx)
	}, nil
}
