package rbac_test

import (
	"errors"
	"testing"

	"github.com/gp-system/auth/rbac"
)

func TestCheckRole(t *testing.T) {
	t.Run("no identity", func(t *testing.T) {
		if err := rbac.CheckRole(nil, "admin"); !errors.Is(err, rbac.ErrUnauthenticated) {
			t.Errorf("err = %v, want errors.Is rbac.ErrUnauthenticated", err)
		}
	})

	t.Run("wrong role", func(t *testing.T) {
		id := &rbac.Identity{Roles: []string{"viewer"}}
		if err := rbac.CheckRole(id, "admin"); !errors.Is(err, rbac.ErrForbidden) {
			t.Errorf("err = %v, want errors.Is rbac.ErrForbidden", err)
		}
	})

	t.Run("matching role", func(t *testing.T) {
		id := &rbac.Identity{Roles: []string{"admin"}}
		if err := rbac.CheckRole(id, "admin"); err != nil {
			t.Errorf("err = %v, want nil", err)
		}
	})
}

func TestCheckPermission(t *testing.T) {
	t.Run("wrong permission", func(t *testing.T) {
		id := &rbac.Identity{Permissions: []string{"read:news"}}
		if err := rbac.CheckPermission(id, "write:news"); !errors.Is(err, rbac.ErrForbidden) {
			t.Errorf("err = %v, want errors.Is rbac.ErrForbidden", err)
		}
	})

	t.Run("matching permission", func(t *testing.T) {
		id := &rbac.Identity{Permissions: []string{"write:news"}}
		if err := rbac.CheckPermission(id, "write:news"); err != nil {
			t.Errorf("err = %v, want nil", err)
		}
	})
}
