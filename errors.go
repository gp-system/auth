package auth

import "errors"

// Errors returned by Identify. Callers decide how to render them; this
// package never writes an HTTP response itself.
var (
	// ErrMissingToken means the request carried no bearer token.
	ErrMissingToken = errors.New("auth: missing bearer token")
	// ErrInvalidToken means the token failed signature, expiry, issuer or
	// audience validation. Wrapped around the underlying jwt error, so
	// errors.Is against jwt sentinels (e.g. jwt.ErrTokenExpired) still works.
	ErrInvalidToken = errors.New("auth: invalid or expired token")
	// ErrInvalidClaims means the token was valid but toIdentity rejected its
	// claims.
	ErrInvalidClaims = errors.New("auth: invalid token claims")
)
