package cryptoutils

import (
	"bytes"
	"crypto/x509"
	"testing"
)

func TestGenerateRSAKey(t *testing.T) {
	key, err := GenerateRSAKey()
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}
	if key.N.BitLen() != 4096 {
		t.Errorf("Expected 4096 bit key, got %d", key.N.BitLen())
	}
}

func TestGenerateECCKey(t *testing.T) {
	key, err := GenerateECCKey()
	if err != nil {
		t.Fatalf("Failed to generate ECC key: %v", err)
	}
	if key.Curve.Params().Name != "P-384" {
		t.Errorf("Expected P-384 curve, got %s", key.Curve.Params().Name)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key, _ := GenerateRSAKey()
	passphrase := []byte("test-pass")

	encrypted, err := EncryptPrivateKey(key, passphrase)
	if err != nil {
		t.Fatalf("Failed to encrypt key: %v", err)
	}

	decrypted, err := LoadEncryptedPrivateKey(encrypted, passphrase)
	if err != nil {
		t.Fatalf("Failed to decrypt key: %v", err)
	}

	// Проверка через сравнение публичных ключей
	pub1, _ := x509.MarshalPKIXPublicKey(key.Public())
	pub2, _ := x509.MarshalPKIXPublicKey(decrypted.Public())

	if !bytes.Equal(pub1, pub2) {
		t.Errorf("Decrypted key does not match original")
	}
}