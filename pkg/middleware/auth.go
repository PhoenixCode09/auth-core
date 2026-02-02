package middleware

import (
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/yourorg/auth-core/pkg/auth"
	"github.com/yourorg/auth-core/pkg/models"
)

// AuthMiddleware valida Authorization: Bearer <token> y coloca el user en ctx.Locals("auth_user_id").
func AuthMiddleware(svc *auth.Service) fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing authorization header"})
		}
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid authorization header"})
		}
		token := parts[1]
		user, err := svc.ValidateAccessToken(c.UserContext(), token)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid token"})
		}
		c.Locals("auth_user_id", user.ID)
		c.Locals("auth_user", user)
		return c.Next()
	}
}

// RequireRole crea un middleware que revisa que el usuario tenga alguno de los roles dados.
func RequireRole(roles ...string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		uIfc := c.Locals("auth_user")
		if uIfc == nil {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
		}
		user, ok := uIfc.(*models.User)
		if !ok {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
		}
		if len(roles) == 0 {
			return c.Next()
		}
		for _, need := range roles {
			if hasRole(user, need) {
				return c.Next()
			}
		}
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
	}
}

func hasRole(u *models.User, role string) bool {
	for _, r := range u.Roles {
		if r.Name == role {
			return true
		}
	}
	return false
}
