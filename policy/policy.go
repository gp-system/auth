// Package policy provides Laravel-style per-user authorization checks that
// narrow RBAC permissions: a permission says the caller may perform an
// operation in general, a policy decides whether they may perform it on
// this particular request (ownership, tenancy, state).
//
// Operations opt in declaratively via the @permission / @policy TypeSpec
// decorators, which surface as x-permission / x-policy OpenAPI extensions
// and are recorded per operation in the generated PermissionByOperation /
// PolicyByOperation maps. The Enforcer strict-server middleware consults
// those maps and runs the named policy from a Registry. Policies receive the
// authenticated rbac.Identity and the fully-bound generated <Op>Request
// struct (body, query, and path parameters).
//
// Every rejection is a plain error, never a rendered response: Deny wraps
// rbac.ErrForbidden and carries a client-safe Detail, and enforce returns
// rbac.ErrUnauthenticated / rbac.ErrForbidden directly. Callers map these to
// their protocol's response shape (see the gpsystem kit's server package for
// an HTTP mapping).
package policy

import (
	"context"
	"fmt"

	"github.com/gp-system/auth/rbac"
)

// Func is one policy check. req is the generated <Op>Request struct for the
// operation the policy guards; policies type-assert it to reach the body and
// parameters. Return nil to allow, Deny (or any error) to block.
type Func func(ctx context.Context, id *rbac.Identity, req any) error

// Denial is the error Deny returns: errors.Is(err, rbac.ErrForbidden) is
// true for it, and Detail is safe to show to the client.
type Denial struct {
	Detail string
}

func (d *Denial) Error() string { return "policy: denied: " + d.Detail }

// Unwrap makes errors.Is(err, rbac.ErrForbidden) true for a *Denial.
func (d *Denial) Unwrap() error { return rbac.ErrForbidden }

// Deny returns a *Denial with the given detail, for policies to signal a
// per-user refusal with a meaningful, client-safe message.
func Deny(detail string) error { return &Denial{Detail: detail} }

// Registry maps policy names, as referenced by @policy("...") in TypeSpec,
// to their implementations. Operations tagged with an unregistered name fail
// closed (see enforce).
type Registry struct {
	funcs map[string]Func
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{funcs: make(map[string]Func)}
}

// Register adds a named policy. Registering the same name twice panics:
// it is a wiring bug, not a runtime condition.
func (r *Registry) Register(name string, fn Func) {
	if _, dup := r.funcs[name]; dup {
		panic(fmt.Sprintf("policy: %q registered twice", name))
	}
	r.funcs[name] = fn
}

// Get looks up a registered policy by name. It is nil-receiver-safe: a nil
// Registry (fail-closed default) reports every name as not found.
func (r *Registry) Get(name string) (Func, bool) {
	if r == nil {
		return nil, false
	}
	fn, ok := r.funcs[name]
	return fn, ok
}

// enforce is the router-agnostic core used by Enforcer. Untagged
// operations pass through without an identity.
// Tagged operations require one (rbac.ErrUnauthenticated), the permission
// check runs before the policy (rbac.ErrForbidden), and a tagged-but-
// unregistered policy name fails closed with a plain error distinct from
// both, since that is a wiring bug rather than a runtime authorization
// outcome.
func enforce(ctx context.Context, reg *Registry, permissions, policies map[string]string, operationID string, req any) error {
	perm, hasPerm := permissions[operationID]
	name, hasPolicy := policies[operationID]
	if !hasPerm && !hasPolicy {
		return nil
	}
	id := rbac.FromContext(ctx)
	if id == nil {
		return rbac.ErrUnauthenticated
	}
	if hasPerm && !id.HasPermission(perm) {
		return rbac.ErrForbidden
	}
	if hasPolicy {
		fn, ok := reg.Get(name)
		if !ok {
			return fmt.Errorf("policy: %q required by operation %q is not registered", name, operationID)
		}
		return fn(ctx, id, req)
	}
	return nil
}
