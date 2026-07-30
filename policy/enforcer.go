package policy

import (
	"context"
	"net/http"
)

// Enforcer enforces authorization for net/http strict servers (chi).
// Wire it after server.StrictValidator in the middleware slice so
// authorization runs before validation:
//
//	gen.NewStrictHandlerWithOptions(handler, []gen.StrictMiddlewareFunc{
//		server.StrictValidator[gen.StrictHandlerFunc](nil),
//		policy.Enforcer[gen.StrictHandlerFunc](reg,
//			gen.PermissionByOperation, gen.PolicyByOperation),
//	}, opts)
func Enforcer[H ~func(ctx context.Context, w http.ResponseWriter, r *http.Request, request any) (any, error)](
	reg *Registry, permissions, policies map[string]string,
) func(f H, operationID string) H {
	return func(f H, operationID string) H {
		return func(ctx context.Context, w http.ResponseWriter, r *http.Request, request any) (any, error) {
			if err := enforce(ctx, reg, permissions, policies, operationID, request); err != nil {
				return nil, err
			}
			return f(ctx, w, r, request)
		}
	}
}
