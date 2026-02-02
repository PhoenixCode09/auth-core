package handlers

import (
	"context"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/yourorg/auth-core/pkg/auth"
	"github.com/yourorg/auth-core/pkg/middleware"
)

// RegisterRoutes monta las rutas de autenticación en el router proporcionado.
func RegisterRoutes(app fiber.Router, svc *auth.Service) {
	// rate limiter config: 5 requests por minuto por IP para endpoints sensibles
	max := 5
	window := 1 * time.Minute

	app.Post("/register", makeRegisterHandler(svc))
	app.Post("/login", middleware.RateLimit(max, window), makeLoginHandler(svc))
	app.Post("/refresh", makeRefreshHandler(svc))
	app.Post("/logout", makeLogoutHandler(svc))
	app.Get("/me", makeMeHandler(svc))
	app.Post("/reset/request", middleware.RateLimit(max, window), makeResetRequestHandler(svc))
	app.Post("/reset/confirm", makeResetConfirmHandler(svc))
	// Roles and user-role management (admin required)
	app.Post("/roles", makeEnsureRoleHandler(svc))
	app.Post("/users/:id/roles", makeAssignRoleHandler(svc))
}

// ----- Handlers -----

func makeRegisterHandler(svc *auth.Service) fiber.Handler {
	type req struct {
		Email    string `json:"email"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	type resp struct {
		ID    string   `json:"id"`
		Email string   `json:"email"`
		Roles []string `json:"roles"`
	}

	return func(c *fiber.Ctx) error {
		var r req
		if err := c.BodyParser(&r); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid payload"})
		}
		user, err := svc.Register(context.Background(), r.Email, r.Username, r.Password)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		// reload user to fetch roles
		u, _ := svc.GetUserByID(context.Background(), user.ID)
		roles := []string{}
		for _, rr := range u.Roles {
			roles = append(roles, rr.Name)
		}
		return c.Status(fiber.StatusCreated).JSON(resp{ID: user.ID, Email: user.Email, Roles: roles})
	}
}

func makeLoginHandler(svc *auth.Service) fiber.Handler {
	type req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	return func(c *fiber.Ctx) error {
		var r req
		if err := c.BodyParser(&r); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid payload"})
		}
		access, refresh, err := svc.Login(context.Background(), r.Email, r.Password)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid credentials"})
		}
		return c.JSON(fiber.Map{"access_token": access, "refresh_token": refresh, "expires_in": int(svc.Config().JWTExpiry.Seconds())})
	}
}

func makeRefreshHandler(svc *auth.Service) fiber.Handler {
	type req struct {
		RefreshToken string `json:"refresh_token"`
	}
	return func(c *fiber.Ctx) error {
		var r req
		if err := c.BodyParser(&r); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid payload"})
		}
		access, refresh, err := svc.Refresh(context.Background(), r.RefreshToken)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid refresh token"})
		}
		return c.JSON(fiber.Map{"access_token": access, "refresh_token": refresh, "expires_in": int(svc.Config().JWTExpiry.Seconds())})
	}
}

func makeLogoutHandler(svc *auth.Service) fiber.Handler {
	type req struct {
		RefreshToken string `json:"refresh_token"`
	}
	return func(c *fiber.Ctx) error {
		var r req
		if err := c.BodyParser(&r); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid payload"})
		}
		if err := svc.Logout(context.Background(), r.RefreshToken); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		return c.SendStatus(fiber.StatusNoContent)
	}
}

func makeMeHandler(svc *auth.Service) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// support Authorization header
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "missing token"})
		}
		// expect Bearer token
		var token string
		_, err := fmt.Sscanf(authHeader, "Bearer %s", &token)
		if err != nil || token == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid token"})
		}
		user, err := svc.ValidateAccessToken(context.Background(), token)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid token"})
		}
		roles := []string{}
		for _, rr := range user.Roles {
			roles = append(roles, rr.Name)
		}
		return c.JSON(fiber.Map{"id": user.ID, "email": user.Email, "roles": roles})
	}
}

func makeResetRequestHandler(svc *auth.Service) fiber.Handler {
	type req struct {
		Email string `json:"email"`
	}
	return func(c *fiber.Ctx) error {
		var r req
		if err := c.BodyParser(&r); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid payload"})
		}
		token, err := svc.RequestPasswordReset(context.Background(), r.Email)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed"})
		}
		// for demo we return the token (in prod send email)
		return c.Status(fiber.StatusAccepted).JSON(fiber.Map{"reset_token": token})
	}
}

func makeResetConfirmHandler(svc *auth.Service) fiber.Handler {
	type req struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	return func(c *fiber.Ctx) error {
		var r req
		if err := c.BodyParser(&r); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid payload"})
		}
		if err := svc.ConfirmPasswordReset(context.Background(), r.Token, r.NewPassword); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		return c.SendStatus(fiber.StatusOK)
	}
}

func makeEnsureRoleHandler(svc *auth.Service) fiber.Handler {
	type req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	return func(c *fiber.Ctx) error {
		var r req
		if err := c.BodyParser(&r); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid payload"})
		}
		if err := svc.EnsureRole(context.Background(), r.Name, r.Description); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		return c.SendStatus(fiber.StatusCreated)
	}
}

func makeAssignRoleHandler(svc *auth.Service) fiber.Handler {
	type req struct {
		Role string `json:"role"`
	}
	return func(c *fiber.Ctx) error {
		userID := c.Params("id")
		var r req
		if err := c.BodyParser(&r); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid payload"})
		}
		if err := svc.AssignRoleToUser(context.Background(), userID, r.Role); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		return c.SendStatus(fiber.StatusOK)
	}
}
