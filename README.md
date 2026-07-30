# auth

JWT issuing/parsing, an `rbac` subpackage for role/permission checks over an
authenticated identity, and a `policy` subpackage for declarative per-request
authorization checks that narrow RBAC permissions to a specific resource.

`auth` is developed as part of the [gp-system](https://github.com/gp-system)
tooling but has no dependency on it or on any other gp-system package: its
only dependency is
[`github.com/golang-jwt/jwt/v5`](https://github.com/golang-jwt/jwt). It is
also transport-agnostic: nothing in this module writes an HTTP response, so
it works equally well behind `net/http`, a WebSocket handshake, gRPC
metadata, or anything else that can hand it a bearer token.

## The problem it solves

Most backends need three related but distinct things: mint and verify
signed tokens, decide "is this caller allowed to do this kind of thing at
all" (RBAC), and decide "is this caller allowed to do this to *this
particular* resource" (ownership, tenancy, state). `auth` provides all
three as small, composable pieces instead of one framework-shaped
middleware: `TokenIssuer` for JWTs, `rbac` for role/permission checks, and
`policy` for the per-request checks that RBAC alone can't express.

Every rejection is a plain Go error, never a rendered response. Callers
decide how to turn `ErrMissingToken`, `rbac.ErrForbidden` and friends into
whatever their protocol needs. The gpsystem kit, for example, maps them onto
RFC 9457 Problems in its `server` package; a standalone caller can do
something as small as `http.Error(w, err.Error(), status)`.

## Install

```sh
go get github.com/gp-system/auth
```

## Usage

### Issuing and verifying tokens

```go
cfg := auth.Config{
	Secret:    os.Getenv("JWT_SECRET"),
	AccessTTL: 15 * time.Minute,
	Issuer:    "my-service",
}

issuer := auth.NewTokenIssuer[auth.DefaultClaims](cfg)
claims := auth.NewDefaultClaims(cfg, user.ID, user.Username, user.Roles, user.Permissions)
token, err := issuer.Sign(claims)
```

`Config` is meant to be embedded under a prefix with an env-loading library
such as `caarlos0/env`:

```go
type Config struct {
	JWT auth.Config `envPrefix:"JWT_"`
}
```

`NewRefreshToken` returns a 32-byte random hex string for a separate,
long-lived refresh flow; store only a hash of it server-side.

### Identify: bearer token to identity

`Identify` extracts the bearer token from an Authorization header value,
verifies it, and maps the claims onto an `*rbac.Identity`. It takes a header
value, not a request, and never writes a response:

```go
id, err := auth.Identify(issuer, auth.DefaultIdentity, r.Header.Get("Authorization"))
switch {
case errors.Is(err, auth.ErrMissingToken), errors.Is(err, auth.ErrInvalidToken), errors.Is(err, auth.ErrInvalidClaims):
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return
case err != nil:
	http.Error(w, "internal error", http.StatusInternalServerError)
	return
}
ctx := rbac.WithIdentity(r.Context(), id)
```

Wrapping that in a `net/http` middleware is a handful of lines; see
[standalone usage](#standalone-net-http-example) below for a full example.
Applications with custom claims write their own `toIdentity` function
instead of `auth.DefaultIdentity`.

### rbac: role and permission checks

```go
if err := rbac.CheckRole(id, "admin"); err != nil {
	// errors.Is(err, rbac.ErrUnauthenticated) or errors.Is(err, rbac.ErrForbidden)
}
if err := rbac.CheckPermission(id, "write:news"); err != nil {
	// same two sentinels
}
```

`rbac.FromContext` reads the identity back out in handlers and services;
`Identity.HasRole` / `Identity.HasPermission` are nil-receiver-safe.

### policy: per-request authorization

A permission says a caller may perform an operation in general; a policy
decides whether they may perform it on *this* request (its body, query and
path parameters). Operations opt into a permission and/or a named policy
declaratively, via two maps from operation ID to permission name and to
policy name; `Enforcer` wires an oapi-codegen strict-server middleware that
consults those maps:

```go
reg := policy.NewRegistry()
reg.Register("news.owner", func(ctx context.Context, id *rbac.Identity, req any) error {
	r := req.(gen.UpdateNewsRequestObject)
	if r.AuthorID != id.Subject {
		return policy.Deny("not the owner")
	}
	return nil
})

gen.NewStrictHandlerWithOptions(handler, []gen.StrictMiddlewareFunc{
	policy.Enforcer[gen.StrictHandlerFunc](reg, gen.PermissionByOperation, gen.PolicyByOperation),
}, opts)
```

`gen.PermissionByOperation` and `gen.PolicyByOperation` here are just
`map[string]string` values keyed by operation ID; a hand-written map works
exactly the same way as a generated one. When used with the gpsystem kit's
code generator, TypeSpec `@permission`/`@policy` decorators emit those maps
automatically (as `x-permission`/`x-policy` OpenAPI extensions turned into
Go maps), but that generation step is an optional convenience, not a
requirement for using `policy` on its own.

An operation tagged with a permission or policy requires an identity
(`rbac.ErrUnauthenticated`); the permission check runs before the policy
(`rbac.ErrForbidden`); `policy.Deny` returns a `*policy.Denial`, which also
satisfies `errors.Is(err, rbac.ErrForbidden)` and carries a client-safe
`Detail`; a tagged-but-unregistered policy name fails closed with a plain
error distinct from both sentinels, since that is a wiring bug rather than a
runtime authorization outcome.

### Standalone net/http example

A complete, runnable example with no gp-system dependency beyond this
module lives in the gpsystem docs: see the "Using auth standalone" guide at
`gpsystem-docs/content/en/12.auth/4.standalone.md` (and its Hungarian
mirror). It shows a hand-written `net/http` middleware built on `Identify`
and `rbac.CheckRole`, a `policy.Registry` wired by hand, and a non-HTTP
example (checking a token inside a WebSocket handshake) to demonstrate the
module has no transport assumptions.

## Design rules

- **Claims-generic tokens.** `TokenIssuer[C]` is generic over the claims
  type so asymmetric algorithms or app-specific claims shapes can be added
  without breaking the default `DefaultClaims` consumers.
- **RBAC has no opinion on where roles come from.** `rbac` only reads and
  checks the `Identity` already in context; anything can populate it, not
  just this package's own `Identify`.
- **Policies fail closed.** A nil `Registry`, and an operation whose
  declared policy name was never registered, both deny rather than allow.
- **Errors, not responses.** Every rejection (missing token, wrong role,
  missing permission, policy denial) is a plain Go error identified by a
  sentinel (`errors.Is`) or a small typed value (`errors.As`). Nothing in
  this module writes to an `http.ResponseWriter` or imports an error
  framework; rendering is entirely the caller's decision.
