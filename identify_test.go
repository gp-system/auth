package auth_test

import (
	"errors"
	"testing"

	"github.com/gp-system/auth"
	"github.com/gp-system/auth/rbac"
)

func TestBearerToken(t *testing.T) {
	cases := []struct {
		header string
		want   string
		ok     bool
	}{
		{"", "", false},
		{"Bearer", "", false},
		{"Bearer ", "", false},
		{"Basic dXNlcjpwYXNz", "", false},
		{"Bearer abc.def.ghi", "abc.def.ghi", true},
		{"bearer abc.def.ghi", "abc.def.ghi", true},
		{"Bearer   abc.def.ghi  ", "abc.def.ghi", true},
	}
	for _, tc := range cases {
		got, ok := auth.BearerToken(tc.header)
		if got != tc.want || ok != tc.ok {
			t.Errorf("BearerToken(%q) = %q, %v; want %q, %v", tc.header, got, ok, tc.want, tc.ok)
		}
	}
}

func TestIdentify(t *testing.T) {
	issuer := auth.NewTokenIssuer[auth.DefaultClaims](cfg)
	token, err := issuer.Sign(auth.NewDefaultClaims(cfg, "user-1", "peter", []string{"admin"}, []string{"write:news"}))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("missing token", func(t *testing.T) {
		_, err := auth.Identify(issuer, auth.DefaultIdentity, "")
		if !errors.Is(err, auth.ErrMissingToken) {
			t.Errorf("err = %v, want errors.Is auth.ErrMissingToken", err)
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		_, err := auth.Identify(issuer, auth.DefaultIdentity, "Bearer not-a-jwt")
		if !errors.Is(err, auth.ErrInvalidToken) {
			t.Errorf("err = %v, want errors.Is auth.ErrInvalidToken", err)
		}
	})

	t.Run("toIdentity rejects claims", func(t *testing.T) {
		reject := func(auth.DefaultClaims) (*rbac.Identity, error) {
			return nil, errors.New("no thanks")
		}
		_, err := auth.Identify(issuer, reject, "Bearer "+token)
		if !errors.Is(err, auth.ErrInvalidClaims) {
			t.Errorf("err = %v, want errors.Is auth.ErrInvalidClaims", err)
		}
	})

	t.Run("valid token", func(t *testing.T) {
		id, err := auth.Identify(issuer, auth.DefaultIdentity, "Bearer "+token)
		if err != nil {
			t.Fatal(err)
		}
		if id.Subject != "user-1" || !id.HasRole("admin") {
			t.Errorf("identity = %+v", id)
		}
	})
}

// TestIdentifyWithRBAC composes Identify with rbac.CheckRole the way a
// caller-written middleware would, without any transport or response
// concern: this package only ever returns errors.
func TestIdentifyWithRBAC(t *testing.T) {
	issuer := auth.NewTokenIssuer[auth.DefaultClaims](cfg)
	adminToken, _ := issuer.Sign(auth.NewDefaultClaims(cfg, "u1", "peter", []string{"admin"}, nil))
	userToken, _ := issuer.Sign(auth.NewDefaultClaims(cfg, "u2", "bob", []string{"user"}, nil))

	authorize := func(authorization string) error {
		id, err := auth.Identify(issuer, auth.DefaultIdentity, authorization)
		if err != nil {
			return err
		}
		return rbac.CheckRole(id, "admin")
	}

	cases := []struct {
		name          string
		authorization string
		wantErr       error
	}{
		{"no token", "", auth.ErrMissingToken},
		{"garbage", "Bearer garbage", auth.ErrInvalidToken},
		{"wrong role", "Bearer " + userToken, rbac.ErrForbidden},
		{"admin", "Bearer " + adminToken, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := authorize(tc.authorization)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("err = %v, want errors.Is %v", err, tc.wantErr)
			}
		})
	}
}
