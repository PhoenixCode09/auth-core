package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

// KeyProvider abstracts how keys are loaded/stored.
type KeyProvider interface {
	GetPrivateKeyPEM() ([]byte, error)
	GetPublicKeyPEM() ([]byte, error)
}

// FileKeyProvider is a simple KeyProvider that loads keys from files.
type FileKeyProvider struct {
	PrivPath string
	PubPath  string
}

func NewFileKeyProvider(privPath, pubPath string) *FileKeyProvider {
	return &FileKeyProvider{PrivPath: privPath, PubPath: pubPath}
}

func (f *FileKeyProvider) GetPrivateKeyPEM() ([]byte, error) {
	if f.PrivPath == "" {
		return nil, fmt.Errorf("private key path is empty")
	}
	b, err := ioutil.ReadFile(f.PrivPath)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (f *FileKeyProvider) GetPublicKeyPEM() ([]byte, error) {
	if f.PubPath == "" {
		return nil, fmt.Errorf("public key path is empty")
	}
	b, err := ioutil.ReadFile(f.PubPath)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// ParsePrivateKey parses a PEM encoded private key to *rsa.PrivateKey.
func ParsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return key, nil
	}
	// try PKCS8
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsakey, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA private key")
	}
	return rsakey, nil
}

// ParsePublicKey parses a PEM encoded public key to *rsa.PublicKey.
func ParsePublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	pubIfc, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err == nil {
		pub, ok := pubIfc.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA public key")
		}
		return pub, nil
	}
	// try ParseCertificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err == nil {
		if pub, ok := cert.PublicKey.(*rsa.PublicKey); ok {
			return pub, nil
		}
	}
	return nil, err
}
