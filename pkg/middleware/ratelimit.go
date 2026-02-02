package middleware

import (
	"net"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
)

type bucket struct {
	count     int
	expiresAt time.Time
}

var rl = struct {
	sync.Mutex
	m map[string]*bucket
}{m: make(map[string]*bucket)}

// RateLimit returns a Fiber handler that limits requests per key (by IP) to max within window.
func RateLimit(max int, window time.Duration) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ip := c.IP()
		if ip == "" {
			// fallback to remote addr
			host, _, err := net.SplitHostPort(c.Context().RemoteAddr().String())
			if err == nil {
				ip = host
			}
		}
		now := time.Now()
		rl.Lock()
		b, ok := rl.m[ip]
		if !ok || now.After(b.expiresAt) {
			rl.m[ip] = &bucket{count: 1, expiresAt: now.Add(window)}
			rl.Unlock()
			return c.Next()
		}
		if b.count >= max {
			rl.Unlock()
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{"error": "rate limit exceeded"})
		}
		b.count++
		rl.Unlock()
		return c.Next()
	}
}
