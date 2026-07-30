package auth

import (
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/gp-system/auth/rbac"
)

// BearerToken extracts the token from an Authorization header value of the
// form "Bearer <token>". It reports false when the header is empty or does
// not carry that scheme.
func BearerToken(header string) (string, bool) {
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	return strings.TrimSpace(header[len(prefix):]), true
}

// Identify turns an Authorization header value into an rbac.Identity: it
// extracts the bearer token, parses and validates it with issuer, and maps
// the resulting claims with toIdentity. It has no opinion on transport (it
// takes a header value, not a *http.Request) and never writes a response;
// callers render the returned error however fits their protocol.
//
// Errors are ErrMissingToken, ErrInvalidToken (wrapping the underlying jwt
// error) or ErrInvalidClaims (wrapping the toIdentity error).
func Identify[C jwt.Claims](issuer *TokenIssuer[C], toIdentity func(C) (*rbac.Identity, error), authorization string) (*rbac.Identity, error) {
	token, ok := BearerToken(authorization)
	if !ok {
		return nil, ErrMissingToken
	}

	claims, err := issuer.Parse(token)
	if err != nil {
		return nil, err
	}

	id, err := toIdentity(claims)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidClaims, err)
	}
	return id, nil
}

// DefaultIdentity maps DefaultClaims onto rbac.Identity. It is the
// toIdentity function Middleware-style helpers use for the common case;
// applications with custom claims write their own.
func DefaultIdentity(c DefaultClaims) (*rbac.Identity, error) {
	return &rbac.Identity{
		Subject:     c.Subject,
		Username:    c.Username,
		Roles:       c.Roles,
		Permissions: c.Permissions,
	}, nil
}
