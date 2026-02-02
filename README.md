# authcore

Framework de autenticación en Go (esqueleto + demo).

Este repositorio contiene un framework de autenticación "auth-core" escrito en Go.

Quickstart demo

1. Compilar:

```powershell
go build ./...
```

2. Ejecutar demo (levanta Fiber en :3000, crea `demo.db` SQLite en el directorio):

```powershell
go run ./cmd/demo
```

3. Probar (ejemplos curl):

- Registro:

```powershell
curl -X POST http://localhost:3000/api/auth/register -H "Content-Type: application/json" -d "{\"email\":\"alice@example.com\",\"username\":\"alice\",\"password\":\"Password123!\"}"
```

- Login:

```powershell
curl -X POST http://localhost:3000/api/auth/login -H "Content-Type: application/json" -d "{\"email\":\"alice@example.com\",\"password\":\"Password123!\"}"
```

- Obtener recurso protegido (ejemplo):

```powershell
curl -H "Authorization: Bearer <ACCESS_TOKEN>" http://localhost:3000/api/private
```

Documentación OpenAPI (Swagger UI)

- El demo sirve la especificación OpenAPI en `/docs/openapi.yaml` y una UI en `/docs`.
- Después de arrancar el demo, visita: `http://localhost:3000/docs`

Uso de claves PEM (producción/demo con archivos)

- Si deseas usar claves RSA desde archivos en lugar de generar en memoria, coloca tus archivos `priv.pem` y `pub.pem` en la raíz del proyecto. El demo detectará automáticamente ambos archivos y usará `FileKeyProvider`.

Generar claves PEM de ejemplo (opcional, local):

```powershell
openssl genpkey -algorithm RSA -out priv.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in priv.pem -out pub.pem
```

Notas

- Esto es un framework que puede integrarse en servicios; el demo expone un servicio REST como ejemplo.
- En producción se recomienda usar Postgres y un KeyVault para llaves privadas.

Siguiente paso: puedo añadir CI (linters/tests) o mejorar la UI de la documentación si quieres.

## Documentación adicional

A continuación tienes un resumen práctico de los endpoints principales, ejemplos de peticiones y cómo integrar el framework en tu aplicación Go.

API Quick Reference

Base URL del demo: `http://localhost:3000` (o `:4000` en `demo/` ejemplo)

- POST /api/auth/register
  - Payload: `{ "email": "a@b.com", "username": "user", "password": "P@ssw0rd" }`
  - Respuesta: 201 Created con `{ id, email, roles }`

- POST /api/auth/login
  - Payload: `{ "email": "a@b.com", "password": "..." }`
  - Respuesta: 200 OK con `{ access_token, refresh_token, expires_in }`

- POST /api/auth/refresh
  - Payload: `{ "refresh_token": "..." }`
  - Respuesta: 200 OK con nuevo `{ access_token, refresh_token }`

- POST /api/auth/logout
  - Payload: `{ "refresh_token": "..." }` — Marca el refresh token como revocado.
  - Respuesta: 204 No Content

- GET /api/auth/me
  - Header: `Authorization: Bearer <ACCESS_TOKEN>`
  - Respuesta: 200 OK con datos de usuario y roles

- POST /api/auth/reset/request
  - Payload: `{ "email": "..." }` — crea un token de reset (demo: devuelve el token)
  - Respuesta: 202 Accepted

- POST /api/auth/reset/confirm
  - Payload: `{ "token": "...", "new_password": "..." }` — confirma reset
  - Respuesta: 200 OK

- POST /api/auth/roles (admin)
  - Payload: `{ "name": "admin", "description": "..." }` — crea o actualiza role
  - Respuesta: 201 Created

- POST /api/auth/users/{id}/roles (admin)
  - Payload: `{ "role": "admin" }` — asigna role al usuario
  - Respuesta: 200 OK

Seguridad y tokens

- Access tokens: JWT RS256, firmados con la clave privada (o proveedor de claves).
- Refresh tokens: UUID opacos almacenados en DB como SHA256 hash; soporta rotación y revocación.
- Passwords: Argon2id para derivación + RSA-OAEP para cifrar el hash (esquema híbrido).

Integración mínima en Go (ejemplo)

1. Configura store y KeyProvider (ejemplo usando archivos PEM o claves en memoria):

```go
st, _ := store.NewGormStore("sqlite.db", true)
kp := crypto.NewFileKeyProvider("priv.pem", "pub.pem") // o memKP
cfg := auth.Config{JWTExpiry: 15*time.Minute, RefreshExpiry: 7*24*time.Hour, Issuer: "my-service"}
svc, _ := auth.NewService(cfg, st, kp)
```

2. Monta handlers en Fiber:

```go
app := fiber.New()
authGroup := app.Group("/api/auth")
handlers.RegisterRoutes(authGroup, svc)
app.Use("/api/private", middleware.AuthMiddleware(svc), middleware.RequireRole("admin"))
```

Notas de configuración

- DB: para demo usamos SQLite (archivo `demo.db`). Para producción usa Postgres (cambia el DSN en `store.NewGormStore`).
- Claves RSA: coloca `priv.pem` y `pub.pem` en la raíz y el demo los usará automáticamente.
- Rate limiting: el framework incluye un middleware simple en memoria (`pkg/middleware/ratelimit.go`); para producción considera un backend centralizado (Redis) si necesitas escalar.

Archivo de peticiones

Se incluye un archivo `.http_request` en la raíz con ejemplos listos para usar (curl/HTTP requests) para los endpoints principales.

Debugging y pruebas

- Ejecuta `go test ./...` para correr la suite de tests (incluye pruebas E2E en memoria).
- El demo/ contiene un ejemplo de aplicación que muestra cómo consumir el framework desde otra app Go.

Contribuciones y siguientes mejoras sugeridas

- Añadir soporte Redis para rate-limiting y blacklist de JWT.
- Integrar IdentityVault (o similar) para la gestión de claves privadas.
- Añadir OpenAPI más detallado y generación automática de clientes.
