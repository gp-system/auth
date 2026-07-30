package rbac

import "errors"

// Errors returned by CheckRole and CheckPermission. Callers decide how to
// render them; this package never writes a response itself.
var (
	// ErrUnauthenticated means no Identity was supplied (a nil identity).
	ErrUnauthenticated = errors.New("rbac: authentication required")
	// ErrForbidden means the Identity lacks the required role or permission.
	ErrForbidden = errors.New("rbac: insufficient privileges")
)

// CheckRole reports ErrUnauthenticated for a nil identity, ErrForbidden when
// id has none of roles, and nil otherwise.
func CheckRole(id *Identity, roles ...string) error {
	return check(id, roles, (*Identity).HasRole)
}

// CheckPermission is CheckRole for permissions (any-of semantics).
func CheckPermission(id *Identity, perms ...string) error {
	return check(id, perms, (*Identity).HasPermission)
}

func check(id *Identity, want []string, has func(*Identity, ...string) bool) error {
	if id == nil {
		return ErrUnauthenticated
	}
	if !has(id, want...) {
		return ErrForbidden
	}
	return nil
}
