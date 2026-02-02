package test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/yourorg/auth-core/pkg/auth"
	"github.com/yourorg/auth-core/pkg/crypto"
	"github.com/yourorg/auth-core/pkg/handlers"
	"github.com/yourorg/auth-core/pkg/middleware"
	"github.com/yourorg/auth-core/pkg/store"
)

func setupOIDCApp(t *testing.T) (*fiber.App, string) {
	priv, pub, err := crypto.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	kp := &memKP{priv: priv, pub: pub}

	st, err := store.NewGormStore(":memory:", true)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	cfg := auth.Config{JWTExpiry: time.Minute * 5, RefreshExpiry: time.Hour * 24 * 7, Issuer: "http://localhost:8080"}
	svc, err := auth.NewService(cfg, st, kp)
	if err != nil {
		t.Fatalf("new svc: %v", err)
	}

	// create a user
	user, err := svc.Register(context.Background(), "john@example.com", "john", "Password123!")
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	app := fiber.New()
	handlers.RegisterOIDCRoutes(app, svc)
	// mount auth routes too
	authGroup := app.Group("/api/auth")
	handlers.RegisterRoutes(authGroup, svc)
	app.Get("/api/private", middleware.AuthMiddleware(svc), func(c *fiber.Ctx) error { return c.SendString("ok") })
	return app, user.ID
}

func TestOIDCAuthorizeTokenFlow(t *testing.T) {
	app, userID := setupOIDCApp(t)

	// create client
	cli := map[string]string{"client_id": "demo-client", "client_secret": "secret", "redirect_uris": "http://localhost/cb", "grant_types": "authorization_code"}
	b, _ := json.Marshal(cli)
	req := httptest.NewRequest(http.MethodPost, "/oauth/clients", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	res, _ := app.Test(req)
	if res.StatusCode != 201 {
		t.Fatalf("client create failed: %d", res.StatusCode)
	}

	// authorize: simulate user approval by providing user_id
	authURL := "/authorize?response_type=code&client_id=demo-client&redirect_uri=" + url.QueryEscape("http://localhost/cb") + "&state=xyz&user_id=" + url.QueryEscape(userID)
	req = httptest.NewRequest(http.MethodGet, authURL, nil)
	res, _ = app.Test(req)
	if res.StatusCode < 300 || res.StatusCode >= 400 {
		t.Fatalf("authorize redirect expected, got %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if loc == "" {
		t.Fatalf("no redirect location")
	}
	u, _ := url.Parse(loc)
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect")
	}

	// exchange token
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "http://localhost/cb")
	form.Set("client_id", "demo-client")
	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, _ = app.Test(req)
	if res.StatusCode != 200 {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("token exchange failed %d %s", res.StatusCode, string(body))
	}
	var tr map[string]interface{}
	json.NewDecoder(res.Body).Decode(&tr)
	access := tr["access_token"].(string)
	idtok := tr["id_token"].(string)
	refresh := tr["refresh_token"].(string)
	if access == "" || idtok == "" || refresh == "" {
		t.Fatalf("missing tokens")
	}

	// userinfo
	req = httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	res, _ = app.Test(req)
	if res.StatusCode != 200 {
		t.Fatalf("userinfo failed %d", res.StatusCode)
	}

	// introspect
	form = url.Values{}
	form.Set("token", access)
	req = httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, _ = app.Test(req)
	var ir map[string]interface{}
	json.NewDecoder(res.Body).Decode(&ir)
	if ir["active"] != true {
		t.Fatalf("introspect says inactive")
	}

	// revoke (refresh)
	form = url.Values{}
	form.Set("token", refresh)
	req = httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, _ = app.Test(req)
	if res.StatusCode != 200 {
		t.Fatalf("revoke failed %d", res.StatusCode)
	}

	// introspect should now be false for refresh (we only handle refresh revocation) - introspect checks access token so leave as true
}
