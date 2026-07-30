package policy_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/gp-system/auth/policy"
	"github.com/gp-system/auth/rbac"
)

// httpHandlerFunc mirrors the StrictHandlerFunc oapi-codegen generates for
// net/http servers; the enforcer factories are generic over it.
type httpHandlerFunc func(ctx context.Context, w http.ResponseWriter, r *http.Request, request any) (any, error)

type ownerRequest struct{ AuthorID string }

func ownerRegistry(t *testing.T) *policy.Registry {
	t.Helper()
	reg := policy.NewRegistry()
	reg.Register("news.owner", func(_ context.Context, id *rbac.Identity, req any) error {
		r, ok := req.(ownerRequest)
		if !ok {
			return policy.Deny("unexpected request type")
		}
		if r.AuthorID != id.Subject {
			return policy.Deny("not the owner")
		}
		return nil
	})
	return reg
}

func TestEnforcer(t *testing.T) {
	permissions := map[string]string{
		"UpdateNews": "news.write",
		"ListNews":   "news.read",
	}
	policies := map[string]string{
		"UpdateNews": "news.owner",
		"DeleteNews": "news.owner",
		"GhostNews":  "news.ghost", // never registered
	}

	call := func(reg *policy.Registry, operationID string, id *rbac.Identity, req any) (bool, error) {
		called := false
		var next httpHandlerFunc = func(context.Context, http.ResponseWriter, *http.Request, any) (any, error) {
			called = true
			return nil, nil
		}
		mw := policy.Enforcer[httpHandlerFunc](reg, permissions, policies)
		ctx := context.Background()
		if id != nil {
			ctx = rbac.WithIdentity(ctx, id)
		}
		_, err := mw(next, operationID)(ctx, nil, nil, req)
		return called, err
	}

	wantForbidden := func(t *testing.T, err error) *policy.Denial {
		t.Helper()
		if !errors.Is(err, rbac.ErrForbidden) {
			t.Fatalf("err = %v, want errors.Is rbac.ErrForbidden", err)
		}
		var d *policy.Denial
		errors.As(err, &d)
		return d
	}

	owner := &rbac.Identity{Subject: "u1", Permissions: []string{"news.write", "news.read"}}

	t.Run("untagged operation passes without identity", func(t *testing.T) {
		called, err := call(ownerRegistry(t), "HealthCheck", nil, nil)
		if err != nil || !called {
			t.Fatalf("called = %v, err = %v; want pass-through", called, err)
		}
	})

	t.Run("tagged operation without identity is unauthenticated", func(t *testing.T) {
		called, err := call(ownerRegistry(t), "UpdateNews", nil, ownerRequest{AuthorID: "u1"})
		if called {
			t.Fatal("handler ran despite missing identity")
		}
		if !errors.Is(err, rbac.ErrUnauthenticated) {
			t.Fatalf("err = %v, want errors.Is rbac.ErrUnauthenticated", err)
		}
	})

	t.Run("missing permission is forbidden before policy runs", func(t *testing.T) {
		id := &rbac.Identity{Subject: "u1"} // owner, but no news.write
		called, err := call(ownerRegistry(t), "UpdateNews", id, ownerRequest{AuthorID: "u1"})
		if called {
			t.Fatal("handler ran despite missing permission")
		}
		_ = wantForbidden(t, err)
	})

	t.Run("permission ok and policy allows", func(t *testing.T) {
		called, err := call(ownerRegistry(t), "UpdateNews", owner, ownerRequest{AuthorID: "u1"})
		if err != nil || !called {
			t.Fatalf("called = %v, err = %v; want allowed", called, err)
		}
	})

	t.Run("policy denies with detail", func(t *testing.T) {
		called, err := call(ownerRegistry(t), "UpdateNews", owner, ownerRequest{AuthorID: "someone-else"})
		if called {
			t.Fatal("handler ran despite policy denial")
		}
		if d := wantForbidden(t, err); d == nil || d.Detail != "not the owner" {
			t.Fatalf("denial = %+v, want detail %q", d, "not the owner")
		}
	})

	t.Run("policy-only operation needs no permission entry", func(t *testing.T) {
		id := &rbac.Identity{Subject: "u1"}
		called, err := call(ownerRegistry(t), "DeleteNews", id, ownerRequest{AuthorID: "u1"})
		if err != nil || !called {
			t.Fatalf("called = %v, err = %v; want allowed", called, err)
		}
	})

	t.Run("permission-only operation skips registry", func(t *testing.T) {
		called, err := call(policy.NewRegistry(), "ListNews", owner, nil)
		if err != nil || !called {
			t.Fatalf("called = %v, err = %v; want allowed", called, err)
		}
	})

	t.Run("unregistered policy fails closed with plain error", func(t *testing.T) {
		called, err := call(ownerRegistry(t), "GhostNews", owner, nil)
		if called {
			t.Fatal("handler ran despite unregistered policy")
		}
		if err == nil || errors.Is(err, rbac.ErrForbidden) || errors.Is(err, rbac.ErrUnauthenticated) {
			t.Fatalf("err = %v, want a plain wiring error, not an rbac sentinel", err)
		}
	})

	t.Run("nil registry fails closed too", func(t *testing.T) {
		var reg *policy.Registry
		called, err := call(reg, "DeleteNews", owner, ownerRequest{AuthorID: "u1"})
		if called || err == nil {
			t.Fatalf("called = %v, err = %v; want fail-closed", called, err)
		}
	})
}

func TestRegistryDuplicatePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on duplicate registration")
		}
	}()
	reg := policy.NewRegistry()
	fn := func(context.Context, *rbac.Identity, any) error { return nil }
	reg.Register("dup", fn)
	reg.Register("dup", fn)
}
