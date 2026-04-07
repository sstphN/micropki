package cryptoutils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/youmark/pkcs8"
)

func GenerateRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 4096)
}

func GenerateECCKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
}

func EncryptPrivateKey(key crypto.Signer, passphrase []byte) ([]byte, error) {
	// Используем Marshal для создания зашифрованного PKCS8 контейнера
	// Это самый надежный метод в этой библиотеке
	encryptedDer, err := pkcs8.Marshal(key, passphrase, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt key: %w", err)
	}

	block := &pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: encryptedDer,
	}
	return pem.EncodeToMemory(block), nil
}

func LoadEncryptedPrivateKey(pemData, passphrase []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "ENCRYPTED PRIVATE KEY" {
		return nil, fmt.Errorf("invalid PEM block")
	}

	key, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key: %w", err)
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("not a valid signer")
	}
	return signer, nil
}