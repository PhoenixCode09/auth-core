package main

import (
	"fmt"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/yourorg/auth-core/pkg/auth"
	"github.com/yourorg/auth-core/pkg/crypto"
	"github.com/yourorg/auth-core/pkg/handlers"
	"github.com/yourorg/auth-core/pkg/middleware"
	"github.com/yourorg/auth-core/pkg/store"
)

func main() {
	// Demo of using auth-core as a framework (library)
	// This demo is located in /demo and imports the parent module packages.

	// Prepare KeyProvider (in-memory for demo)
	priv, pub, err := crypto.GenerateRSAKeyPair(2048)
	if err != nil {
		log.Fatalf("gen keys: %v", err)
	}
	kp := &memKP{priv: priv, pub: pub}

	// Create store (sqlite demo-demo.db)
	st, err := store.NewGormStore("demo-demo.db", true)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close()

	cfg := auth.Config{JWTExpiry: time.Minute * 15, RefreshExpiry: time.Hour * 24 * 7, Issuer: "auth-core-demo"}

	// Build service using PEMs generated in this demo
	svc, err := auth.NewService(cfg, st, kp)
	if err != nil {
		log.Fatalf("service: %v", err)
	}

	app := fiber.New()
	h := app.Group("/api/auth")
	handlers.RegisterRoutes(h, svc)

	// Protected route with role requirement
	app.Get("/demo/admin", middleware.AuthMiddleware(svc), middleware.RequireRole("admin"), func(c *fiber.Ctx) error {
		return c.SendString("hello admin")
	})

	fmt.Println("Demo server for framework usage running on :4000")
	if err := app.Listen(":4000"); err != nil {
		log.Fatal(err)
	}
}

// memKP locally for demo usage
type memKP struct{ priv, pub []byte }

func (m *memKP) GetPrivateKeyPEM() ([]byte, error) { return m.priv, nil }
func (m *memKP) GetPublicKeyPEM() ([]byte, error)  { return m.pub, nil }
