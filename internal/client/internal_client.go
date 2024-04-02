package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/wakeful-cloud/pam-oauth/internal/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// InternalClient is the internal server client
type InternalClient struct {
	// Internal server client configuration
	config InternalClientConfig

	// gRPC connection
	conn *grpc.ClientConn

	// gRPC client
	client api.AuthServiceClient
}

// grpcInterceptorLogger is a gRPC interceptor logger
func grpcInterceptorLogger(ctx context.Context, level logging.Level, msg string, fields ...any) {
	slog.Log(ctx, slog.Level(level), msg, fields...)
}

// NewInternalClient creates a new internal server client
func NewInternalClient(config InternalClientConfig) (*InternalClient, error) {
	if config.ServerTlsCert == nil {
		return nil, errors.New("root TLS certificate is required")
	}

	if config.ClientTlsKeypair == nil {
		return nil, errors.New("client TLS keypair is required")
	}

	// Log
	slog.Info("initializing internal server client",
		slog.String("server host", config.Host),
		slog.Int("server port", int(config.Port)),
		slog.String("client tls cert path", config.ClientTlsCertPath),
		slog.String("client tls key path", config.ClientTlsKeyPath),
		slog.String("server tls cert path", config.ServerTlsCertPath),
		slog.Int("timeout", config.Timeout),
	)

	// Create a new TLS certificate pool with just the internal server certificate
	serverCertpool := x509.NewCertPool()
	serverCertpool.AddCert(config.ServerTlsCert)

	// Initialize the gRPC connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	loggingOptions := []logging.Option{
		logging.WithLogOnEvents(logging.StartCall, logging.FinishCall),
	}

	conn, err := grpc.DialContext(ctx,
		fmt.Sprintf("%s:%d", config.Host, config.Port),
		grpc.FailOnNonTempDialError(true),
		grpc.WithBlock(),
		grpc.WithIdleTimeout(10*time.Second),
		grpc.WithReturnConnectionError(),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(4*1024*1024),
			grpc.MaxCallSendMsgSize(4*1024*1024),
		),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{*config.ClientTlsKeypair},
			MinVersion:   tls.VersionTLS13,
			RootCAs:      serverCertpool,
		})),
		grpc.WithChainUnaryInterceptor(
			logging.UnaryClientInterceptor(logging.LoggerFunc(grpcInterceptorLogger), loggingOptions...),
		),
		grpc.WithChainStreamInterceptor(
			logging.StreamClientInterceptor(logging.LoggerFunc(grpcInterceptorLogger), loggingOptions...),
		),
	)

	if err != nil {
		return nil, err
	}

	// Initialize the gRPC client
	client := api.NewAuthServiceClient(conn)

	// Log
	slog.Info("initialized internal server client")

	return &InternalClient{
		config: config,
		conn:   conn,
		client: client,
	}, nil
}

// IssueChallenge issues a challenge for the user to verify its identity
func (client InternalClient) IssueChallenge(username string) (string, string, error) {
	// Issue a challenge
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(client.config.Timeout)*time.Second)
	defer cancel()

	res, err := client.client.IssueChallenge(ctx, &api.IssueChallengeRequest{
		Username: username,
	})

	if err != nil {
		return "", "", err
	}

	// Log
	slog.Debug("issued challenge",
		slog.String("username", username),
		slog.String("challenge ID", res.Id),
		slog.String("url", res.Url),
	)

	return res.Id, res.Url, nil
}

// VerifyChallenge verifies a challenge
func (client InternalClient) VerifyChallenge(id string, code string) (bool, error) {
	// Verify the challenge
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(client.config.Timeout)*time.Second)
	defer cancel()

	res, err := client.client.VerifyChallenge(ctx, &api.VerifyChallengeRequest{
		Id:               id,
		VerificationCode: code,
	})

	if err != nil {
		return false, err
	}

	// Log
	slog.Debug("verified challenge",
		slog.String("challenge ID", id),
		slog.Bool("verified", res.Verified),
	)

	return res.Verified, nil
}

// GetChallengeInfo gets challenge info
func (client InternalClient) GetChallengeInfo(id string) (string, map[string]string, error) {
	// Verify the challenge
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(client.config.Timeout)*time.Second)
	defer cancel()

	res, err := client.client.GetChallengeInfo(ctx, &api.GetChallengeInfoRequest{
		Id: id,
	})

	if err != nil {
		return "", nil, err
	}

	// Log
	slog.Debug("got challenge info",
		slog.String("challenge ID", id),
		slog.String("challenge username", res.Username),
		slog.Any("challenge environment variables", res.Env),
	)

	return res.Username, res.Env, nil
}

// Close closes the internal server client
func (client *InternalClient) Close() error {
	// Close the connection
	err := client.conn.Close()

	if err != nil {
		return err
	}

	return nil
}
