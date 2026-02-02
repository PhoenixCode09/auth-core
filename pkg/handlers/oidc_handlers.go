package handlers

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/yourorg/auth-core/pkg/auth"
)

// RegisterOIDCRoutes registra endpoints OIDC/OAuth2 básicos en el router dado.
func RegisterOIDCRoutes(app fiber.Router, svc *auth.Service) {
	app.Get("/.well-known/openid-configuration", makeDiscoveryHandler(svc))
	app.Get("/jwks.json", makeJWKSHandler(svc))
	app.Get("/authorize", makeAuthorizeHandler(svc))
	app.Post("/token", makeTokenHandler(svc))
	app.Get("/userinfo", makeUserinfoHandler(svc))

	// admin / client registration (for demo) and token introspect/revoke
	app.Post("/oauth/clients", makeCreateClientHandler(svc))
	app.Post("/oauth/introspect", makeIntrospectHandler(svc))
	app.Post("/oauth/revoke", makeRevokeHandler(svc))
}

func makeDiscoveryHandler(svc *auth.Service) fiber.Handler {
	return func(c *fiber.Ctx) error {
		issuer := svc.Config().Issuer
		base := strings.TrimSuffix(issuer, "/")
		cfg := map[string]interface{}{
			"issuer":                                issuer,
			"jwks_uri":                              base + "/jwks.json",
			"authorization_endpoint":                base + "/authorize",
			"token_endpoint":                        base + "/token",
			"userinfo_endpoint":                     base + "/userinfo",
			"response_types_supported":              []string{"code"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}
		return c.JSON(cfg)
	}
}

func makeJWKSHandler(svc *auth.Service) fiber.Handler {
	return func(c *fiber.Ctx) error {
		j, err := svc.JWKS()
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to build jwks"})
		}
		// return raw JSON
		return c.JSON(j)
	}
}

func makeAuthorizeHandler(svc *auth.Service) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// GET /authorize?response_type=code&client_id=&redirect_uri=&scope=&state=&code_challenge=&code_challenge_method=&user_id=
		q := c.Request().URI().QueryString()
		vals, _ := url.ParseQuery(string(q))
		clientID := vals.Get("client_id")
		redirect := vals.Get("redirect_uri")
		state := vals.Get("state")
		codeChallenge := vals.Get("code_challenge")
		codeChallengeMethod := vals.Get("code_challenge_method")
		userID := vals.Get("user_id")
		// Validate client exists and redirect matches
		if clientID == "" || redirect == "" {
			return c.Status(fiber.StatusBadRequest).SendString("missing client_id or redirect_uri")
		}
		// verify redirect in client allowed list
		cli, err := svc.GetOAuthClientByClientID(context.Background(), clientID)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).SendString("unknown client")
		}
		if !isRedirectAllowed(redirect, cli.RedirectURIs) {
			return c.Status(fiber.StatusBadRequest).SendString("redirect_uri not allowed")
		}
		// For a framework, allow a quick path: if user_id provided, create code and redirect
		if userID != "" {
			code, err := svc.CreateAuthCode(context.Background(), clientID, userID, redirect, codeChallenge, codeChallengeMethod, time.Minute*10)
			if err != nil {
				return c.Status(fiber.StatusInternalServerError).SendString("failed to create code")
			}
			// redirect back with code and state
			redir, _ := url.Parse(redirect)
			q2 := redir.Query()
			q2.Set("code", code)
			if state != "" {
				q2.Set("state", state)
			}
			redir.RawQuery = q2.Encode()
			return c.Redirect(redir.String())
		}
		// otherwise return simple HTML login prompt that lets test pass user_id (for demo)
		html := `<html><body>
<form method="get" action="` + c.OriginalURL() + `">
  <label>User ID (for demo): <input name="user_id"/></label>
  <input type="submit" value="Approve"/>
</form>
</body></html>`
		return c.Type("html").SendString(html)
	}
}

func makeTokenHandler(svc *auth.Service) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// support application/x-www-form-urlencoded
		grant := c.FormValue("grant_type")
		if grant == "authorization_code" {
			code := c.FormValue("code")
			redirect := c.FormValue("redirect_uri")
			clientID := c.FormValue("client_id")
			codeVerifier := c.FormValue("code_verifier")
			access, idt, refresh, err := svc.ExchangeAuthCode(context.Background(), code, clientID, redirect, codeVerifier)
			if err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
			}
			return c.JSON(fiber.Map{"access_token": access, "id_token": idt, "refresh_token": refresh, "token_type": "Bearer", "expires_in": int(svc.Config().JWTExpiry.Seconds())})
		}
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "unsupported_grant"})
	}
}

func makeUserinfoHandler(svc *auth.Service) fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing token"})
		}
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid auth header"})
		}
		token := parts[1]
		user, err := svc.ValidateAccessToken(context.Background(), token)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid token"})
		}
		// minimal userinfo
		return c.JSON(fiber.Map{"sub": user.ID, "email": user.Email})
	}
}

func makeCreateClientHandler(svc *auth.Service) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var in struct {
			ClientID     string `json:"client_id"`
			ClientSecret string `json:"client_secret"`
			RedirectURIs string `json:"redirect_uris"`
			GrantTypes   string `json:"grant_types"`
		}
		if err := c.BodyParser(&in); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid payload"})
		}
		cli, err := svc.CreateOAuthClient(context.Background(), in.ClientID, in.ClientSecret, in.RedirectURIs, in.GrantTypes)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		return c.Status(fiber.StatusCreated).JSON(cli)
	}
}

func makeIntrospectHandler(svc *auth.Service) fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := c.FormValue("token")
		if token == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing token"})
		}
		// naive introspect: try parse JWT
		_, err := svc.ValidateAccessToken(context.Background(), token)
		if err != nil {
			return c.JSON(fiber.Map{"active": false})
		}
		return c.JSON(fiber.Map{"active": true})
	}
}

func makeRevokeHandler(svc *auth.Service) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// support refresh token revocation
		token := c.FormValue("token")
		if token == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "missing token"})
		}
		if err := svc.Logout(context.Background(), token); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(fiber.Map{"revoked": true})
	}
}

// helper to check redirect
func isRedirectAllowed(redirect string, allowedCSV string) bool {
	u, err := url.Parse(redirect)
	if err != nil {
		return false
	}
	allowed := strings.Split(allowedCSV, ",")
	for _, a := range allowed {
		if strings.TrimSpace(a) == "" {
			continue
		}
		if a == u.String() || strings.HasPrefix(u.String(), strings.TrimSpace(a)) {
			return true
		}
	}
	return false
}
