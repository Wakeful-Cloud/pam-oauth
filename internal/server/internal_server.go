package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/mitchellh/mapstructure"
	"github.com/wakeful-cloud/pam-oauth/internal/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// grpcInterceptorLogger is a gRPC interceptor logger
func grpcInterceptorLogger(ctx context.Context, level logging.Level, msg string, fields ...any) {
	slog.Log(ctx, slog.Level(level), msg, fields...)
}

// InitInternalServer initializes the internal gRPC server, returning a shutdown function and an error (if any)
func InitInternalServer(config InternalServerConfig, challengeManager *ChallengeManager) (func() error, error) {
	if config.RootTlsCert == nil {
		return nil, errors.New("root TLS certificate is required")
	}

	if config.ServerTlsKeypair == nil {
		return nil, errors.New("server TLS keypair is required")
	}

	// Log
	slog.Info("starting internal server",
		slog.String("listening address", config.Address),
		slog.Int("listening port", int(config.Port)),
	)

	// Create a new TLS certificate pool with just the client root certificate
	rootCertpool := x509.NewCertPool()
	rootCertpool.AddCert(config.RootTlsCert.Leaf)

	// Initialize the gRPC server
	loggingOptions := []logging.Option{
		logging.WithLogOnEvents(logging.StartCall, logging.FinishCall),
	}

	server := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates:             []tls.Certificate{*config.ServerTlsKeypair},
			ClientAuth:               tls.RequireAndVerifyClientCert,
			MinVersion:               tls.VersionTLS13,
			PreferServerCipherSuites: true,
			ClientCAs:                rootCertpool,
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				// Ensure the client certificate is in the allow list
				if len(rawCerts) == 0 {
					return errors.New("no client certificate provided")
				}

				// Check if the client certificate is in the allow list
				clientCert := verifiedChains[0][0]
				ok, err := config.ClientAllowList.Check(clientCert)

				if err != nil {
					return err
				}

				if !ok {
					// Log the client certificate
					slog.Error("client certificate does not match allow list entry",
						slog.String("common name", clientCert.Subject.CommonName),
						slog.String("issuer", clientCert.Issuer.String()),
						slog.String("serial number", clientCert.SerialNumber.String()),
						slog.String("signature algorithm", clientCert.SignatureAlgorithm.String()),
						slog.String("signature", hex.EncodeToString(clientCert.Signature)),
						slog.String("valid from", clientCert.NotBefore.String()),
						slog.String("valid to", clientCert.NotAfter.String()),
						slog.Any("key usage", EncodeKeyUsage(clientCert.KeyUsage)),
						slog.Any("ext key usage", EncodeExtKeyUsage(clientCert.ExtKeyUsage)),
					)

					return errors.New("client certificate not in allow list or does not match allow list entry")
				}

				return nil
			},
		})),
		grpc.ConnectionTimeout(5*time.Second),
		grpc.MaxRecvMsgSize(4*1024*1024),
		grpc.MaxSendMsgSize(4*1024*1024),
		grpc.ChainUnaryInterceptor(
			logging.UnaryServerInterceptor(logging.LoggerFunc(grpcInterceptorLogger), loggingOptions...),
		),
		grpc.ChainStreamInterceptor(
			logging.StreamServerInterceptor(logging.LoggerFunc(grpcInterceptorLogger), loggingOptions...),
		),
	)

	// Register the services
	api.RegisterAuthServiceServer(server, &AuthService{
		challengeManager: challengeManager,
	})

	// Initialize a new listener
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", config.Address, config.Port))

	if err != nil {
		return nil, err
	}

	// Start the server
	go func() {
		err := server.Serve(listener)

		if err != nil && !errors.Is(err, net.ErrClosed) {
			// Log
			slog.Error("internal server error",
				slog.Any("error", err),
			)

			panic(err)
		}
	}()

	return func() error {
		server.GracefulStop()

		return nil
	}, nil
}

// AuthService is the gRPC authentication service
type AuthService struct {
	api.UnimplementedAuthServiceServer

	// challengeManager is the challengeManager manager
	challengeManager *ChallengeManager
}

// IssueChallenge issues a challenge for the client to verify its identity
func (service *AuthService) IssueChallenge(ctx context.Context, req *api.IssueChallengeRequest) (*api.IssueChallengeResponse, error) {
	// Issue a new challenge
	id, url, err := service.challengeManager.Step1(req.Username)

	if err != nil {
		return nil, err
	}

	return &api.IssueChallengeResponse{
		Id:  id,
		Url: url,
	}, nil
}

// VerifyChallenge verifies a challenge
func (service *AuthService) VerifyChallenge(ctx context.Context, req *api.VerifyChallengeRequest) (*api.VerifyChallengeResponse, error) {
	// Verify the challenge
	verified, err := service.challengeManager.Step4(req.Id, req.VerificationCode)

	if err != nil {
		return nil, err
	}

	return &api.VerifyChallengeResponse{
		Verified: verified,
	}, nil
}

// GetChallengeInfo gets challenge environment variables
func (service *AuthService) GetChallengeInfo(ctx context.Context, req *api.GetChallengeInfoRequest) (*api.GetChallengeInfoResponse, error) {
	// Get the usernamd and challenge environment variables
	username, env, err := service.challengeManager.Step5(req.Id)

	if err != nil {
		return nil, err
	}

	// Build the response
	res := &api.GetChallengeInfoResponse{
		Username: username,
	}

	err = mapstructure.Decode(env, &res.Env)

	if err != nil {
		return nil, err
	}

	return res, nil
}
