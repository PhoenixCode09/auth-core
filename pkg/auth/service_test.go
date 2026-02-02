package auth

import (
	"context"
	"testing"
	"time"

	"github.com/yourorg/auth-core/pkg/crypto"
	"github.com/yourorg/auth-core/pkg/store"
)

// memKeyProvider for tests
type memKP struct {
	priv []byte
	pub  []byte
}

func (m *memKP) GetPrivateKeyPEM() ([]byte, error) { return m.priv, nil }
func (m *memKP) GetPublicKeyPEM() ([]byte, error)  { return m.pub, nil }

func TestRegisterLoginRefreshFlow(t *testing.T) {
	// generate keys
	priv, pub, err := crypto.GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	kp := &memKP{priv: priv, pub: pub}

	// create store (sqlite in-memory)
	st, err := store.NewGormStore(":memory:", true)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer st.Close()

	cfg := Config{JWTExpiry: time.Minute * 5, RefreshExpiry: time.Hour * 24, Issuer: "test"}
	svc, err := NewService(cfg, st, kp)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	ctx := context.Background()

	// register
	user, err := svc.Register(ctx, "alice@example.com", "alice", "Password123!")
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if user.Email != "alice@example.com" {
		t.Fatalf("unexpected email")
	}

	// login
	access, refresh, err := svc.Login(ctx, "alice@example.com", "Password123!")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if access == "" || refresh == "" {
		t.Fatalf("empty tokens")
	}

	// refresh
	newAccess, newRefresh, err := svc.Refresh(ctx, refresh)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if newAccess == "" || newRefresh == "" {
		t.Fatalf("empty new tokens")
	}

	// using the same refresh again should fail because was revoked
	_, _, err = svc.Refresh(ctx, refresh)
	if err == nil {
		t.Fatalf("expected refresh with old token to fail")
	}

	// sanity: refresh with newRefresh should succeed
	_, _, err = svc.Refresh(ctx, newRefresh)
	if err != nil {
		t.Fatalf("refresh with new token failed: %v", err)
	}

	// small wait to ensure tokens have different jti (not strictly required)
	time.Sleep(10 * time.Millisecond)
}
