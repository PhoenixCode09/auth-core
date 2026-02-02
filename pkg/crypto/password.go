package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"

	"golang.org/x/crypto/argon2"
)

// Parameters for Argon2id. These are conservative defaults; tune for your environment.
const (
	argonTime    = 1
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	saltLen      = 16
)

// HashPassword deriva un hash con Argon2id y lo cifra con la clave pública provista por KeyProvider.
// Retorna salt (raw) y encHash (base64 encoded) para almacenar.
func HashPassword(password string, kp KeyProvider) (salt []byte, encHash []byte, err error) {
	// generar salt
	salt = make([]byte, saltLen)
	if _, err = io.ReadFull(rand.Reader, salt); err != nil {
		return nil, nil, err
	}
	// derivar
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	// obtener clave pública
	pubPem, err := kp.GetPublicKeyPEM()
	if err != nil {
		return nil, nil, err
	}
	pub, err := ParsePublicKey(pubPem)
	if err != nil {
		return nil, nil, err
	}

	// cifrar hash con RSA-OAEP
	enc, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, hash, nil)
	if err != nil {
		return nil, nil, err
	}

	encB64 := base64.StdEncoding.EncodeToString(enc)
	return salt, []byte(encB64), nil
}

// VerifyPassword verifica una contraseña: desencripta el encHash usando la clave privada del kp, deriva
// el hash del password con el salt y compara.
func VerifyPassword(password string, salt []byte, encHash []byte, kp KeyProvider) (bool, error) {
	// obtener private pem
	privPem, err := kp.GetPrivateKeyPEM()
	if err != nil {
		return false, err
	}
	priv, err := ParsePrivateKey(privPem)
	if err != nil {
		return false, err
	}

	// decodificar base64
	encBytes, err := base64.StdEncoding.DecodeString(string(encHash))
	if err != nil {
		return false, err
	}

	// desencriptar
	plain, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encBytes, nil)
	if err != nil {
		return false, err
	}

	// derivar nuevo hash
	newHash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	// comparar en tiempo constante
	if subtleCompare(newHash, plain) {
		return true, nil
	}
	return false, nil
}

// subtleCompare realiza comparación en tiempo constante
func subtleCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var res byte
	for i := 0; i < len(a); i++ {
		res |= a[i] ^ b[i]
	}
	return res == 0
}

// GenerateRSAKeyPair genera una pareja RSA en memoria y devuelve PEM-encoded bytes (PKCS1 private, PKIX public)
func GenerateRSAKeyPair(bits int) (privPem, pubPem []byte, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	privDER := x509.MarshalPKCS1PrivateKey(priv)
	privBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privDER}
	privPem = pem.EncodeToMemory(privBlock)

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	pubBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}
	pubPem = pem.EncodeToMemory(pubBlock)
	return privPem, pubPem, nil
}
