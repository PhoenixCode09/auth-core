package test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/yourorg/auth-core/pkg/auth"
	"github.com/yourorg/auth-core/pkg/crypto"
	"github.com/yourorg/auth-core/pkg/handlers"
	"github.com/yourorg/auth-core/pkg/middleware"
	"github.com/yourorg/auth-core/pkg/store"
)

// memKeyProvider for tests
type memKP struct {
	priv []byte
	pub  []byte
}

func (m *memKP) GetPrivateKeyPEM() ([]byte, error) { return m.priv, nil }
func (m *memKP) GetPublicKeyPEM() ([]byte, error)  { return m.pub, nil }

func setupApp(t *testing.T) *fiber.App {
	priv, pub, err := crypto.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	kp := &memKP{priv: priv, pub: pub}

	st, err := store.NewGormStore(":memory:", true)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	cfg := auth.Config{JWTExpiry: time.Minute * 5, RefreshExpiry: time.Hour * 24 * 7, Issuer: "test"}
	svc, err := auth.NewService(cfg, st, kp)
	if err != nil {
		t.Fatalf("new svc: %v", err)
	}

	app := fiber.New()
	h := app.Group("/api/auth")
	handlers.RegisterRoutes(h, svc)
	app.Get("/api/private", middleware.AuthMiddleware(svc), func(c *fiber.Ctx) error {
		return c.SendString("ok")
	})
	return app
}

func TestE2ERegisterLoginProtected(t *testing.T) {
	app := setupApp(t)

	// register
	reqBody := map[string]string{"email": "bob@example.com", "username": "bob", "password": "P@ssw0rd"}
	b, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := app.Test(req)
	if resp.StatusCode != 201 {
		t.Fatalf("expected 201 got %d", resp.StatusCode)
	}

	// login
	b, _ = json.Marshal(map[string]string{"email": "bob@example.com", "password": "P@ssw0rd"})
	req = httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, _ = app.Test(req)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 got %d", resp.StatusCode)
	}
	var lr map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&lr)
	access := lr["access_token"].(string)

	// access protected
	req = httptest.NewRequest(http.MethodGet, "/api/private", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	resp, _ = app.Test(req)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 got %d", resp.StatusCode)
	}
}
