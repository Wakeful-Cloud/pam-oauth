package server

import (
	context "context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/erni27/imcache"
	"github.com/wakeful-cloud/pam-oauth/internal/common"
	"golang.org/x/oauth2"
)

type challengeState int

const (
	// challengeStateStep1 is the first step of the challenge
	challengeStateStep1 challengeState = iota

	// challengeStateStep2 is the second step of the challenge
	challengeStateStep2

	// challengeStateStep3 is the third step of the challenge
	challengeStateStep3

	// challengeStateStep4 is the fourth step of the challenge
	challengeStateStep4
)

// challenge is the challenge information
type challenge struct {
	// The most-recent challenge state
	state challengeState

	// The username of the user
	username string

	// The OAuth verifier
	oAuthVerifier string

	// The OAuth callback URL
	oAuthUrl string

	// The verification code sent to the user after completing the OAuth flow to verify the user
	// attempting to login via the PAM module is the same user that completed the OAuth flow
	verificationCode string

	// The challenge environment variables
	env map[string]string

	// The client certificate
	clientCert *x509.Certificate
}

// ChallengeManager is the global challenge manager
type ChallengeManager struct {
	// The global configuration
	config Config

	// The OIDC provider
	oidcProvider *oidc.Provider

	// The OIDC verifier
	oidcVerifier *oidc.IDTokenVerifier

	// The OAuth config
	oauthConfig *oauth2.Config

	// Challenges indexed by ID
	challenges *imcache.Cache[string, challenge]
}

// NewChallengeManager creates a new challenge manager
func NewChallengeManager(config Config) (*ChallengeManager, error) {
	// Initialize the challenges
	challenges := &ChallengeManager{
		config: config,
		challenges: imcache.New[string, challenge](
			imcache.WithDefaultExpirationOption[string, challenge](time.Duration(config.InternalServerConfig.Timeout) * time.Second),
		),
	}

	// Initialize the OIDC provider
	var endpoint oauth2.Endpoint
	if config.OAuthClient.OidcUrl != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var err error
		challenges.oidcProvider, err = oidc.NewProvider(ctx, config.OAuthClient.OidcUrl)

		if err != nil {
			return nil, err
		}

		endpoint = challenges.oidcProvider.Endpoint()

		// Initialize the OIDC verifier
		challenges.oidcVerifier = challenges.oidcProvider.Verifier(&oidc.Config{
			ClientID: config.OAuthClient.ClientID,
		})
	} else {
		endpoint = oauth2.Endpoint{
			AuthURL:  config.OAuthClient.AuthURL,
			TokenURL: config.OAuthClient.TokenURL,
		}
	}

	// Generate the callback URL
	redirectUrl, err := url.Parse(config.OAuthServer.ExternalBaseUrl)

	if err != nil {
		return nil, err
	}

	redirectUrl = redirectUrl.JoinPath("oauth", "end")

	// Generate the OAuth config
	challenges.oauthConfig = &oauth2.Config{
		ClientID:     config.OAuthClient.ClientID,
		ClientSecret: config.OAuthClient.ClientSecret,
		Endpoint:     endpoint,
		RedirectURL:  redirectUrl.String(),
		Scopes:       config.OAuthClient.Scopes,
	}

	return challenges, nil
}

// Step1 issues a challenge for the user to verify its identity, returning the challenge ID and flow begin URL (Called by the gRPC server)
func (challengeManager *ChallengeManager) Step1(username string, clientCert *x509.Certificate) (string, string, error) {
	// Generate the challenge ID
	challengeId, err := generateRandomBase32(common.CHALLENGE_ID_LENGTH)

	if err != nil {
		return "", "", err
	}

	// Generate the flow begin URL (Which just redirects to the OAuth URL to reduce the length of the message)
	flowBeginUrl, err := generateFlowBeginUrl(challengeId, challengeManager.config.OAuthServer)

	if err != nil {
		return "", "", err
	}

	// Log
	slog.Debug("issued challenge",
		slog.String("username", username),
		slog.String("challenge ID", challengeId),
	)

	// Initialize a new challenge
	challenge := challenge{
		state:      challengeStateStep1,
		username:   username,
		clientCert: clientCert,
	}
	challengeManager.challenges.Set(challengeId, challenge, imcache.WithDefaultExpiration())

	return challengeId, flowBeginUrl, nil
}

// Step2 returns the OAuth URL (Called by the web server)
func (challengeManager *ChallengeManager) Step2(challengeId string) (string, error) {
	// Get the challenge
	challenge, ok := challengeManager.challenges.Get(challengeId)

	if !ok {
		return "", errors.New("invalid challenge")
	}

	// Check that the challenge is in the correct state
	if challenge.state != challengeStateStep1 {
		return "", errors.New("invalid challenge state")
	}

	// Ensure the OAuth URL is not already generated
	if challenge.oAuthUrl != "" {
		return "", errors.New("OAuth URL already generated")
	}

	// Generate the callback URL
	verifier := oauth2.GenerateVerifier()
	oAuthUrl := challengeManager.oauthConfig.AuthCodeURL(challengeId, oauth2.AccessTypeOnline, oauth2.S256ChallengeOption(verifier))

	// Update the challenge
	challenge.state = challengeStateStep2
	challenge.oAuthVerifier = verifier
	challenge.oAuthUrl = oAuthUrl

	ok = challengeManager.challenges.Replace(challengeId, challenge, imcache.WithDefaultExpiration())
	if !ok {
		return "", errors.New("challenge deleted before OAuth URL could be generated")
	}

	// Log
	slog.Debug("exchanged challenge ID for OAuth URL",
		slog.String("challenge ID", challengeId),
		slog.String("OAuth URL", oAuthUrl),
	)

	return challenge.oAuthUrl, nil
}

// Step3 exchanges the specified OAuth code, invokes the callback expression, generates the challenge info, generates
// the verification code, and returns the verification code and/or if the challenge is succesful (Called by the web server)
func (challengeManager *ChallengeManager) Step3(challengeId string, oauthCode string) (string, string, error) {
	// Get the challenge
	challenge, ok := challengeManager.challenges.Get(challengeId)

	if !ok {
		return "", "", errors.New("invalid challenge")
	}

	// Check that the challenge is in the correct state
	if challenge.state != challengeStateStep2 {
		return "", "", errors.New("invalid challenge state")
	}

	// Exchange the OAuth code for a token
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	token, err := challengeManager.oauthConfig.Exchange(ctx, oauthCode, oauth2.AccessTypeOnline, oauth2.VerifierOption(challenge.oAuthVerifier))

	if err != nil {
		return "", "", err
	}

	// Initialize the callback expression environment
	env := callbackExpressionEnv{
		Username:     challenge.username,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		OauthToken: callbackExpressionEnvOauthToken{
			Expiry: token.Expiry,
			Type:   token.TokenType,
		},
		ClientCert: callbackExpressionEnvClientCert{
			Subject:            challenge.clientCert.Subject.String(),
			Issuer:             challenge.clientCert.Issuer.String(),
			DnsSans:            challenge.clientCert.DNSNames,
			IpSans:             challenge.clientCert.IPAddresses,
			SerialNumber:       challenge.clientCert.SerialNumber.String(),
			Signature:          hex.EncodeToString(challenge.clientCert.Signature),
			SignatureAlgorithm: challenge.clientCert.SignatureAlgorithm.String(),
			ValidFrom:          challenge.clientCert.NotBefore,
			ValidTo:            challenge.clientCert.NotAfter,
			KeyUsage:           EncodeKeyUsage(challenge.clientCert.KeyUsage),
			ExtKeyUsage:        EncodeExtKeyUsage(challenge.clientCert.ExtKeyUsage),
		},
	}

	// Verify the token (if the OIDC verifier is available)
	if challengeManager.oidcVerifier != nil {
		// Extract the raw ID token
		rawIdToken, ok := token.Extra("id_token").(string)

		if !ok {
			return "", "", errors.New("missing ID token")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		// Verify the ID token
		idToken, err := challengeManager.oidcVerifier.Verify(ctx, rawIdToken)

		if err != nil {
			return "", "", err
		}

		// Get the claims
		claims := map[string]any{}
		err = idToken.Claims(&claims)

		if err != nil {
			return "", "", err
		}

		// Update the info
		env.IdToken = callbackExpressionEnvIdtoken{
			AccessTokenHash: idToken.AccessTokenHash,
			Audience:        idToken.Audience,
			Claims:          claims,
			Expiry:          idToken.Expiry,
			IssuedAt:        idToken.IssuedAt,
			Issuer:          idToken.Issuer,
			Nonce:           idToken.Nonce,
			Raw:             rawIdToken,
			Subject:         idToken.Subject,
		}
	}

	// Log
	slog.Debug("evaluating callback expression",
		slog.String("challenge ID", challengeId),
		slog.String("expression", challengeManager.config.InternalServerConfig.Callback),
		slog.Any("info", env),
	)

	// Evaluate callback expression
	res, err := evaluateCallbackExpression(challengeManager.config.InternalServerConfig.Callback, env)

	if err != nil {
		return "", "", err
	}

	if !res.Ok {
		return "", res.Message, nil
	}

	// Generate the verification code
	verificationCode, err := generateRandomNumeric(common.VERIFICATION_CODE_LENGTH)

	if err != nil {
		return "", "", err
	}

	// Update the challenge
	challenge.state = challengeStateStep3
	challenge.verificationCode = verificationCode

	ok = challengeManager.challenges.Replace(challengeId, challenge, imcache.WithDefaultExpiration())

	if !ok {
		return "", "", errors.New("challenge deleted before verification code could be generated")
	}

	// Log
	slog.Debug("exchanged OAuth code for token",
		slog.String("challenge ID", challengeId),
		slog.String("OAuth code", oauthCode),
		slog.String("OAuth token", token.AccessToken),
	)

	return challenge.verificationCode, "Your verification code is:", nil
}

// Step4 verifies the verification code for the specified challenge (Called by the gRPC server)
func (challengeManager *ChallengeManager) Step4(challengeId string, verificationCode string, clientCert *x509.Certificate) (bool, error) {
	// Get the challenge
	challenge, ok := challengeManager.challenges.Get(challengeId)

	if !ok {
		return false, errors.New("invalid challenge")
	}

	// Check that the challenge is in the correct state
	if challenge.state != challengeStateStep3 {
		return false, errors.New("invalid challenge state")
	}

	// Check that the client certificate matches the original client certificate
	if !clientCert.Equal(challenge.clientCert) {
		return false, errors.New("client certificate does not match original client certificate")
	}

	// Verify the code
	verified := challenge.verificationCode == verificationCode

	// Log
	slog.Info("verification status",
		slog.String("challenge ID", challengeId),
		slog.Bool("verified", verified),
	)

	if !verified {
		// Delete the challenge
		ok = challengeManager.challenges.Remove(challengeId)

		if !ok {
			return false, errors.New("challenge deleted before challenge could be deleted")
		}

		return false, nil
	}

	// Update the challenge
	challenge.state = challengeStateStep4
	ok = challengeManager.challenges.Replace(challengeId, challenge, imcache.WithDefaultExpiration())

	if !ok {
		return false, errors.New("challenge deleted before verification code could be verified")
	}

	return true, nil
}

// Step5 returns the username and challenge environment variables for the specified challenge (Called by the gRPC server)
func (challengeManager *ChallengeManager) Step5(challengeId string, clientCert *x509.Certificate) (string, map[string]string, error) {
	// Get the challenge
	challenge, ok := challengeManager.challenges.Get(challengeId)

	if !ok {
		return "", nil, errors.New("invalid challenge")
	}

	// Check that the challenge is in the correct state
	if challenge.state != challengeStateStep4 {
		return "", nil, errors.New("invalid challenge state")
	}

	// Check that the client certificate matches the original client certificate
	if !clientCert.Equal(challenge.clientCert) {
		return "", nil, errors.New("client certificate does not match original client certificate")
	}

	// Delete the challenge
	ok = challengeManager.challenges.Remove(challengeId)

	if !ok {
		return "", nil, errors.New("challenge deleted before challenge info could be returned")
	}

	return challenge.username, challenge.env, nil
}
