package auth_test

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/gp-system/auth"
)

var cfg = auth.Config{
	Secret:    "test-secret-please-rotate",
	AccessTTL: time.Minute,
	Issuer:    "gpsystem-test",
}

func TestTokenRoundTrip(t *testing.T) {
	issuer := auth.NewTokenIssuer[auth.DefaultClaims](cfg)
	claims := auth.NewDefaultClaims(cfg, "user-1", "peter", []string{"admin"}, []string{"write:news"})

	token, err := issuer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := issuer.Parse(token)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Subject != "user-1" || parsed.Username != "peter" {
		t.Errorf("claims lost: %+v", parsed)
	}
	if len(parsed.Roles) != 1 || parsed.Roles[0] != "admin" {
		t.Errorf("roles lost: %+v", parsed.Roles)
	}
}

func TestParseRejectsTamperedToken(t *testing.T) {
	issuer := auth.NewTokenIssuer[auth.DefaultClaims](cfg)
	token, _ := issuer.Sign(auth.NewDefaultClaims(cfg, "u", "", nil, nil))

	tampered := token[:len(token)-2] + "xx"
	_, err := issuer.Parse(tampered)
	if err == nil {
		t.Fatal("tampered token accepted")
	}
	if !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("err = %v, want errors.Is auth.ErrInvalidToken", err)
	}
}

func TestParseRejectsWrongSecret(t *testing.T) {
	other := cfg
	other.Secret = "different"
	token, _ := auth.NewTokenIssuer[auth.DefaultClaims](other).Sign(auth.NewDefaultClaims(other, "u", "", nil, nil))

	if _, err := auth.NewTokenIssuer[auth.DefaultClaims](cfg).Parse(token); err == nil {
		t.Fatal("token signed with another secret accepted")
	}
}

func TestParseRejectsAlgNone(t *testing.T) {
	// alg=none "signed" token must never validate (algorithm confusion).
	unsigned := jwt.NewWithClaims(jwt.SigningMethodNone, auth.NewDefaultClaims(cfg, "u", "", nil, nil))
	token, err := unsigned.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auth.NewTokenIssuer[auth.DefaultClaims](cfg).Parse(token); err == nil {
		t.Fatal("alg=none token accepted")
	}
}

func TestParseRejectsExpired(t *testing.T) {
	short := cfg
	short.AccessTTL = -time.Minute
	issuer := auth.NewTokenIssuer[auth.DefaultClaims](cfg)
	token, _ := issuer.Sign(auth.NewDefaultClaims(short, "u", "", nil, nil))

	_, err := issuer.Parse(token)
	if err == nil {
		t.Fatal("expired token accepted")
	}
	if !errors.Is(err, jwt.ErrTokenExpired) {
		t.Errorf("err = %v, want errors.Is jwt.ErrTokenExpired", err)
	}
	if !errors.Is(err, auth.ErrInvalidToken) {
		t.Errorf("err = %v, want errors.Is auth.ErrInvalidToken", err)
	}
}

func TestParseRejectsWrongIssuer(t *testing.T) {
	other := cfg
	other.Issuer = "someone-else"
	token, _ := auth.NewTokenIssuer[auth.DefaultClaims](other).Sign(auth.NewDefaultClaims(other, "u", "", nil, nil))

	if _, err := auth.NewTokenIssuer[auth.DefaultClaims](cfg).Parse(token); err == nil {
		t.Fatal("token with wrong issuer accepted")
	}
}

func TestParseValidatesAudience(t *testing.T) {
	svcA := cfg
	svcA.Audience = "service-a"
	svcB := cfg
	svcB.Audience = "service-b"

	tokenForA, _ := auth.NewTokenIssuer[auth.DefaultClaims](svcA).Sign(
		auth.NewDefaultClaims(svcA, "u", "", nil, nil))

	// Same audience: accepted.
	if _, err := auth.NewTokenIssuer[auth.DefaultClaims](svcA).Parse(tokenForA); err != nil {
		t.Fatalf("token rejected by its own audience: %v", err)
	}
	// Different audience: rejected (cross-service replay blocked).
	if _, err := auth.NewTokenIssuer[auth.DefaultClaims](svcB).Parse(tokenForA); err == nil {
		t.Fatal("token minted for service-a accepted by service-b")
	}
}

func TestParseRequiresAudienceWhenConfigured(t *testing.T) {
	// A token minted without an aud claim must be rejected by a verifier that
	// requires one.
	noAud := cfg
	tokenNoAud, _ := auth.NewTokenIssuer[auth.DefaultClaims](noAud).Sign(
		auth.NewDefaultClaims(noAud, "u", "", nil, nil))

	withAud := cfg
	withAud.Audience = "service-a"
	if _, err := auth.NewTokenIssuer[auth.DefaultClaims](withAud).Parse(tokenNoAud); err == nil {
		t.Fatal("token without aud accepted by audience-requiring verifier")
	}
}

func TestNewRefreshTokenIsRandom(t *testing.T) {
	a, err := auth.NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := auth.NewRefreshToken()
	if len(a) != 64 || a == b {
		t.Errorf("refresh tokens look wrong: %q %q", a, b)
	}
}
