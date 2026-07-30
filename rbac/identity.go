// Package rbac provides role/permission checks over an authenticated
// Identity carried in the request context. It makes no assumptions about
// where roles come from: the auth middleware (or anything else) populates
// the Identity.
package rbac

import (
	"context"
	"slices"
)

// Identity is the authenticated caller as seen by authorization checks and
// business logic. Extra carries claim data beyond the standard fields.
type Identity struct {
	Subject     string
	Username    string
	Roles       []string
	Permissions []string
	Extra       map[string]any
}

// HasRole reports whether the identity has any of the given roles. Safe to
// call on a nil identity (reports false), matching the nil FromContext can
// return.
func (id *Identity) HasRole(roles ...string) bool {
	if id == nil {
		return false
	}
	for _, r := range roles {
		if slices.Contains(id.Roles, r) {
			return true
		}
	}
	return false
}

// HasPermission reports whether the identity has any of the given
// permissions. Safe to call on a nil identity (reports false), matching the
// nil FromContext can return.
func (id *Identity) HasPermission(perms ...string) bool {
	if id == nil {
		return false
	}
	for _, p := range perms {
		if slices.Contains(id.Permissions, p) {
			return true
		}
	}
	return false
}

type identityKey struct{}

// WithIdentity returns a context carrying the identity. Called by the auth
// middleware; handlers and services read it back with FromContext.
func WithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, identityKey{}, id)
}

// FromContext returns the authenticated identity, or nil when the request
// did not pass auth middleware.
func FromContext(ctx context.Context) *Identity {
	id, _ := ctx.Value(identityKey{}).(*Identity)
	return id
}
