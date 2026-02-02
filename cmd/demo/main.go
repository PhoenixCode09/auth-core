package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/yourorg/auth-core/pkg/auth"
	"github.com/yourorg/auth-core/pkg/crypto"
	"github.com/yourorg/auth-core/pkg/handlers"
	"github.com/yourorg/auth-core/pkg/middleware"
	"github.com/yourorg/auth-core/pkg/store"
)

// memKeyProvider simple KeyProvider en memoria para demo
type memKeyProvider struct {
	priv []byte
	pub  []byte
}

func (m *memKeyProvider) GetPrivateKeyPEM() ([]byte, error) { return m.priv, nil }
func (m *memKeyProvider) GetPublicKeyPEM() ([]byte, error)  { return m.pub, nil }

func main() {
	privPath := "priv.pem"
	pubPath := "pub.pem"

	var kp crypto.KeyProvider
	// if PEM files exist, use FileKeyProvider
	if _, err := os.Stat(privPath); err == nil {
		if _, err := os.Stat(pubPath); err == nil {
			kp = crypto.NewFileKeyProvider(privPath, pubPath)
			fmt.Println("Using FileKeyProvider with priv.pem and pub.pem")
		}
	}

	// fallback: generate keys in memory
	if kp == nil {
		priv, pub, err := crypto.GenerateRSAKeyPair(2048)
		if err != nil {
			log.Fatalf("failed generate keys: %v", err)
		}
		kp = &memKeyProvider{priv: priv, pub: pub}
		fmt.Println("Generated in-memory RSA keys for demo (priv/pub)")
	}

	// crear store sqlite demo.db
	st, err := store.NewGormStore("demo.db", true)
	if err != nil {
		log.Fatalf("failed create store: %v", err)
	}
	defer st.Close()

	cfg := auth.Config{
		JWTExpiry:     time.Minute * 15,
		RefreshExpiry: time.Hour * 24 * 7,
		Issuer:        "http://localhost:3000",
	}

	svc, err := auth.NewService(cfg, st, kp)
	if err != nil {
		log.Fatalf("failed create service: %v", err)
	}

	app := fiber.New()

	// montar rutas de auth
	authGroup := app.Group("/api/auth")
	handlers.RegisterRoutes(authGroup, svc)

	// Mount OIDC endpoints at root
	handlers.RegisterOIDCRoutes(app, svc)

	// ruta protegida de ejemplo
	app.Get("/api/private", middleware.AuthMiddleware(svc), func(c *fiber.Ctx) error {
		user := c.Locals("auth_user")
		return c.JSON(fiber.Map{"message": "protected resource", "user": user})
	})

	// serve OpenAPI yaml and simple Swagger UI
	app.Static("/docs/openapi.yaml", "./docs/openapi.yaml")
	app.Get("/docs", func(c *fiber.Ctx) error {
		html := `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>auth-core API docs</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist/swagger-ui.css" />
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist/swagger-ui-bundle.js"></script>
  <script>
    window.onload = function() {
      SwaggerUIBundle({
        url: '/docs/openapi.yaml',
        dom_id: '#swagger-ui'
      });
    };
  </script>
</body>
</html>`
		return c.Type("html").SendString(html)
	})

	addr := ":3000"
	fmt.Printf("Demo server running at http://localhost%s\n", addr)
	fmt.Printf("Docs available at http://localhost:3000/docs\n")
	fmt.Printf("Try: curl -X POST http://localhost:3000/api/auth/register -d '{\"email\":\"alice@example.com\",\"username\":\"alice\",\"password\":\"Password123!\"}' -H 'Content-Type: application/json'\n")

	// start server
	if err := app.Listen(addr); err != nil {
		log.Fatalf("server error: %v", err)
	}
	// cleanup sleep to ensure deferred Close runs on some platforms
	time.Sleep(100 * time.Millisecond)
}
