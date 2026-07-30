// Package auth provides JWT issuing/parsing and Identify, which turns a
// Bearer token into an rbac.Identity. It is transport-agnostic and never
// writes a response: callers (a net/http middleware, a WebSocket handshake,
// anything else) decide how to render the errors it returns.
//
// v1 signs with HS256 (shared secret). The TokenIssuer API is claims-generic
// so asymmetric algorithms can be added without breaking consumers.
package auth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// DefaultClaims is the kit's standard claims shape, compatible with the
// rbac.Identity fields. Applications needing different claims define their
// own type and use NewTokenIssuer / MiddlewareFor with it.
type DefaultClaims struct {
	Username    string   `json:"username,omitempty"`
	Roles       []string `json:"roles,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	jwt.RegisteredClaims
}

// NewDefaultClaims builds DefaultClaims with registered claims (iat, exp,
// iss, sub) stamped from cfg.
func NewDefaultClaims(cfg Config, subject, username string, roles, permissions []string) DefaultClaims {
	now := time.Now()
	return DefaultClaims{
		Username:    username,
		Roles:       roles,
		Permissions: permissions,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			Issuer:    cfg.Issuer,
			Audience:  audienceClaim(cfg.Audience),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(cfg.AccessTTL)),
		},
	}
}

// audienceClaim returns the aud claim for cfg.Audience, or nil when unset so
// no aud is stamped.
func audienceClaim(aud string) jwt.ClaimStrings {
	if aud == "" {
		return nil
	}
	return jwt.ClaimStrings{aud}
}

// TokenIssuer signs and parses tokens carrying claims of type C. C must be a
// struct type (not a pointer) embedding jwt.RegisteredClaims or otherwise
// implementing jwt.Claims.
type TokenIssuer[C jwt.Claims] struct {
	cfg Config
}

// NewTokenIssuer returns a TokenIssuer configured with cfg.
func NewTokenIssuer[C jwt.Claims](cfg Config) *TokenIssuer[C] {
	return &TokenIssuer[C]{cfg: cfg}
}

// Sign signs the claims as-is with HS256. Stamp registered claims before
// calling (NewDefaultClaims does this for DefaultClaims).
func (i *TokenIssuer[C]) Sign(claims C) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(i.cfg.Secret))
	if err != nil {
		return "", fmt.Errorf("auth: sign: %w", err)
	}
	return signed, nil
}

// Parse validates the signature (algorithm pinned to HS256), expiry and,
// when configured, the issuer and audience, and returns the decoded claims.
func (i *TokenIssuer[C]) Parse(tokenStr string) (C, error) {
	var claims C
	ptr, ok := any(&claims).(jwt.Claims)
	if !ok {
		return claims, errors.New("auth: claims type must be a struct implementing jwt.Claims")
	}

	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithExpirationRequired(),
	}
	if i.cfg.Issuer != "" {
		opts = append(opts, jwt.WithIssuer(i.cfg.Issuer))
	}
	if i.cfg.Audience != "" {
		opts = append(opts, jwt.WithAudience(i.cfg.Audience))
	}

	token, err := jwt.ParseWithClaims(tokenStr, ptr, func(*jwt.Token) (any, error) {
		return []byte(i.cfg.Secret), nil
	}, opts...)
	if err != nil {
		return claims, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	if !token.Valid {
		return claims, ErrInvalidToken
	}
	return claims, nil
}

// NewRefreshToken returns a 32-byte cryptographically random hex string.
// Store only a hash of it server-side.
func NewRefreshToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("auth: refresh token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
