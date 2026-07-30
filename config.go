package auth

import "time"

// Config holds JWT settings. Compose under a prefix:
//
//	type Config struct {
//		JWT auth.Config `envPrefix:"JWT_"`
//	}
//
// mapping to JWT_SECRET, JWT_ACCESS_TOKEN_TTL, JWT_REFRESH_TOKEN_TTL,
// JWT_ISSUER, JWT_AUDIENCE.
//
// Set Issuer and Audience (and use a distinct Secret per service) so a token
// minted for one service or environment cannot be replayed against another
// that happens to share the signing secret. When Audience is set, Parse
// requires the token's aud claim to contain it; when Issuer is set, Parse
// requires a matching iss.
type Config struct {
	Secret     string        `env:"SECRET,required"`
	AccessTTL  time.Duration `env:"ACCESS_TOKEN_TTL" envDefault:"15m"`
	RefreshTTL time.Duration `env:"REFRESH_TOKEN_TTL" envDefault:"168h"`
	Issuer     string        `env:"ISSUER"`
	Audience   string        `env:"AUDIENCE"`
}
