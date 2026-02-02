package crypto

import (
	"testing"
)

// memKeyProvider es un KeyProvider en memoria para tests.
type memKeyProvider struct {
	priv []byte
	pub  []byte
}

func (m *memKeyProvider) GetPrivateKeyPEM() ([]byte, error) { return m.priv, nil }
func (m *memKeyProvider) GetPublicKeyPEM() ([]byte, error)  { return m.pub, nil }

func TestHashAndVerifyPassword(t *testing.T) {
	priv, pub, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair error: %v", err)
	}
	kp := &memKeyProvider{priv: priv, pub: pub}

	password := "S3cureP@ssw0rd"
	salt, encHash, err := HashPassword(password, kp)
	if err != nil {
		t.Fatalf("HashPassword error: %v", err)
	}

	ok, err := VerifyPassword(password, salt, encHash, kp)
	if err != nil {
		t.Fatalf("VerifyPassword error: %v", err)
	}
	if !ok {
		t.Fatalf("expected password to verify")
	}
}

func TestVerifyPasswordNegative(t *testing.T) {
	priv, pub, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateRSAKeyPair error: %v", err)
	}
	kp := &memKeyProvider{priv: priv, pub: pub}

	password := "S3cureP@ssw0rd"
	wrong := "wrong-password"
	salt, encHash, err := HashPassword(password, kp)
	if err != nil {
		t.Fatalf("HashPassword error: %v", err)
	}

	ok, err := VerifyPassword(wrong, salt, encHash, kp)
	if err == nil && ok {
		t.Fatalf("expected verify to fail for wrong password")
	}
}
