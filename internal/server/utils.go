package server

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"log/slog"
	"math"
	"math/big"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/expr-lang/expr"
	"github.com/golang-jwt/jwt/v5"
	"github.com/mitchellh/mapstructure"
	"github.com/wakeful-cloud/pam-oauth/internal/common"
)

// OAuthServerConfig is the callback expression environment OAuth token
type callbackExpressionEnvOauthToken struct {
	Expiry time.Time `expr:"expiry"` // The token expiry
	Type   string    `expr:"type"`   // The token type time
}

// callbackExpressionEnvIdtoken is the callback expression environment ID token
type callbackExpressionEnvIdtoken struct {
	AccessTokenHash string         `expr:"accessTokenHash"` // The access token hash
	Audience        []string       `expr:"audience"`        // The audience
	Claims          map[string]any `expr:"claims"`          // The claims
	Expiry          time.Time      `expr:"expiry"`          // The token expiry time
	IssuedAt        time.Time      `expr:"issuedAt"`        // The token issued at time
	Issuer          string         `expr:"issuer"`          // The token issuer
	Nonce           string         `expr:"nonce"`           // The token nonce
	Raw             string         `expr:"raw"`             // The raw token
	Subject         string         `expr:"subject"`         // The token subject
}

// callbackExpressionEnvClientCert is the callback expression environment client certificate
type callbackExpressionEnvClientCert struct {
	Subject            string    `expr:"subject"`            // The certificate subject
	Issuer             string    `expr:"issuer"`             // The certificate issuer
	DnsSans            []string  `expr:"dnsSans"`            // The certificate DNS Subject Alternative Names (SANs)
	IpSans             []net.IP  `expr:"ipSans"`             // The certificate IP Subject Alternative Names (SANs)
	SerialNumber       string    `expr:"serialNumber"`       // The certificate serial number
	Signature          string    `expr:"signature"`          // The certificate signature
	SignatureAlgorithm string    `expr:"signatureAlgorithm"` // The certificate signature algorithm
	ValidFrom          time.Time `expr:"validFrom"`          // The certificate valid from time
	ValidTo            time.Time `expr:"validTo"`            // The certificate valid to time
	KeyUsage           []string  `expr:"keyUsage"`           // The certificate key usage
	ExtKeyUsage        []string  `expr:"extKeyUsage"`        // The certificate extended key usage
}

// callbackExpressionEnv is the callback expression environment
type callbackExpressionEnv struct {
	Username     string                          `expr:"username"`     // The username of the user that initiated the challenge
	AccessToken  string                          `expr:"accessToken"`  // The raw access token
	RefreshToken string                          `expr:"refreshToken"` // The raw refresh token
	OauthToken   callbackExpressionEnvOauthToken `expr:"oauthToken"`   // The OAuth token
	IdToken      callbackExpressionEnvIdtoken    `expr:"idToken"`      // The ID token
	ClientCert   callbackExpressionEnvClientCert `expr:"clientCert"`   // The client certificate
}

// callbackExpressionResult is the callback expression result
type callbackExpressionResult struct {
	Ok      bool              `mapstructure:"ok"`      // Whether or not to allow the user to authenticate
	Message string            `mapstructure:"message"` // The message to show to the user if rejected
	Env     map[string]string `mapstructure:"env"`     // The environment to pass use to the create user command
}

// callbackExpressionParseEmailRes is the callback expression parse email result
type callbackExpressionParseEmailRes struct {
	Ok     bool   `expr:"ok"`     // Whether the email address is valid
	Name   string `expr:"name"`   // The name part of the email address (if any)
	Local  string `expr:"local"`  // The local part of the email address
	Domain string `expr:"domain"` // The domain part of the email address
}

// callbackExpressionParseJwtRes is the callback expression parse JWT result
type callbackExpressionParseJwtRes struct {
	Ok     bool           `expr:"ok"`     // Whether the JWT is valid
	Claims jwt.MapClaims  `expr:"claims"` // The claims of the JWT
	Header map[string]any `expr:"header"` // The header of the JWT
}

// generateRandomBase32 generates a new random base32-encoded string
func generateRandomBase32(length int) (string, error) {
	// Generate the random bytes
	buffer := make([]byte, length)
	_, err := rand.Read(buffer)

	if err != nil {
		return "", err
	}

	// Encode the random bytes
	return base32.StdEncoding.EncodeToString(buffer), nil
}

// generateRandomNumeric generates a new random numeric string (with leading zeros)
func generateRandomNumeric(length int) (string, error) {
	// Generate the random number
	n, err := rand.Int(rand.Reader, big.NewInt(int64(math.Pow10(length))))

	if err != nil {
		return "", err
	}

	// Convert to string with leading zeros
	str := n.String()
	str = strings.Repeat("0", length-len(str)) + str

	return str, nil
}

// generateFlowBeginUrl generates a new OAuth flow begin URL
func generateFlowBeginUrl(challengeId string, serverConfig OAuthServerConfig) (string, error) {
	// Generate the redirect URL
	redirectUrl, err := url.Parse(serverConfig.ExternalBaseUrl)

	if err != nil {
		return "", err
	}

	redirectUrl = redirectUrl.JoinPath("oauth", "begin")

	query := redirectUrl.Query()
	query.Set("challenge", challengeId)
	redirectUrl.RawQuery = query.Encode()

	return redirectUrl.String(), nil
}

// evaluateCallbackExpression evaluates the verified expression with the specified environment
func evaluateCallbackExpression(expression string, env callbackExpressionEnv) (*callbackExpressionResult, error) {
	// Compile the expression
	program, err := expr.Compile(expression,
		expr.Function("parseEmail",
			func(params ...any) (any, error) {
				// Parse the address
				addr, err := mail.ParseAddress(params[0].(string))

				if err != nil {
					// Log
					slog.Warn("Failed to parse email address", "error", err.Error(), "address", params[0].(string))

					return callbackExpressionParseEmailRes{
						Ok:     false,
						Name:   "",
						Local:  "",
						Domain: "",
					}, nil
				}

				// Parse the local and domain parts
				parts := strings.Split(addr.Address, "@")

				if len(parts) != 2 {
					// Log
					slog.Warn("Failed to parse email address", "address", addr.Address)

					return callbackExpressionParseEmailRes{
						Ok:     false,
						Name:   "",
						Local:  "",
						Domain: "",
					}, nil
				}

				local := parts[0]
				domain := parts[1]

				return callbackExpressionParseEmailRes{
					Ok:     true,
					Name:   addr.Name,
					Local:  local,
					Domain: domain,
				}, nil
			},
			new(func(string) (callbackExpressionParseEmailRes, error)),
		),
		expr.Function("parseJwt",
			func(params ...any) (any, error) {
				// Parse the JWT
				claims := jwt.MapClaims{}
				token, err := jwt.ParseWithClaims(params[0].(string), &claims, func(token *jwt.Token) (interface{}, error) {
					return params[1].(string), nil
				})

				if err != nil {
					// Log
					slog.Warn("Failed to parse JWT", "error", err.Error(), "token", params[0].(string))

					return callbackExpressionParseJwtRes{
						Ok:     false,
						Claims: nil,
						Header: nil,
					}, nil
				}

				return callbackExpressionParseJwtRes{
					Ok:     token.Valid,
					Claims: claims,
					Header: token.Header,
				}, nil
			},
			new(func(string, string) (callbackExpressionParseJwtRes, error)),
		),
		expr.Function("execRegex",
			func(params ...any) (any, error) {
				// Parse the pattern
				pattern, err := regexp.Compile(params[0].(string))

				if err != nil {
					return nil, err
				}

				// Execute the pattern
				groups := pattern.FindStringSubmatch(params[1].(string))

				return groups, nil
			},
			new(func(string, string) ([]string, error)),
		),
		expr.Function("execRegexAll",
			func(params ...any) (any, error) {
				// Parse the pattern
				pattern, err := regexp.Compile(params[0].(string))

				if err != nil {
					return nil, err
				}

				// Execute the pattern
				groups := pattern.FindAllStringSubmatch(params[1].(string), -1)

				return groups, nil
			},
			new(func(string, string) ([][]string, error)),
		),
		expr.Function("replaceRegex",
			func(params ...any) (any, error) {
				// Parse the pattern
				pattern, err := regexp.Compile(params[0].(string))

				if err != nil {
					return nil, err
				}

				// Replace the pattern
				replaced := false
				result := pattern.ReplaceAllStringFunc(params[1].(string), func(match string) string {
					if !replaced {
						replaced = true
						return params[2].(string)
					}

					return match
				})

				return result, nil
			},
			new(func(string, string, string) (string, error)),
		),
		expr.Function("replaceRegexAll",
			func(params ...any) (any, error) {
				// Parse the pattern
				pattern, err := regexp.Compile(params[0].(string))

				if err != nil {
					return nil, err
				}

				// Replace the pattern
				result := pattern.ReplaceAllString(params[1].(string), params[2].(string))

				return result, nil
			},
			new(func(string, string, string) (string, error)),
		),
		expr.Function("log",
			func(params ...any) (any, error) {
				// Parse the log level
				level, err := common.ParseLogLevel(common.LogLevel(params[0].(string)))

				if err != nil {
					return nil, err
				}

				// Log
				slog.Log(context.Background(), level, params[1].(string))

				return nil, nil
			},
			new(func(string, string) error),
		),
	)

	if err != nil {
		return nil, err
	}

	// Run the expression
	rawRes, err := expr.Run(program, env)

	if err != nil {
		return nil, err
	}

	// Decode the result
	decodedRes := callbackExpressionResult{}
	err = mapstructure.Decode(rawRes, &decodedRes)

	if err != nil {
		return nil, err
	}

	return &decodedRes, nil
}
