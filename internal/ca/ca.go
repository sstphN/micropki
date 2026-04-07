package ca

import (
	"bytes"
	"crypto"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"micropki/internal/certificates"
	"micropki/internal/cryptoutils"
	"micropki/internal/logger"
)

// InitCA инициализирует Root CA: генерирует ключи, сертификат и сохраняет их.
func InitCA(subject, keyType string, keySize int, passphraseFile, outDir string, validityDays int, logFile string, force bool) error {
	_, err := logger.SetupLogging(logFile, slog.LevelInfo)
	if err != nil {
		return err
	}

	// Валидация размеров ключей
	if keyType == "rsa" && keySize != 4096 {
		return fmt.Errorf("RSA key size must be 4096, got %d", keySize)
	}
	if keyType == "ecc" && keySize != 384 {
		return fmt.Errorf("ECC key size must be 384, got %d", keySize)
	}

	// Чтение парольной фразы
	passData, err := os.ReadFile(passphraseFile)
	if err != nil {
		slog.Error("Failed to read passphrase file", "error", err)
		return err
	}
	passphrase := bytes.TrimSpace(passData)

	// Пути к файлам
	privateDir := filepath.Join(outDir, "private")
	certsDir := filepath.Join(outDir, "certs")
	keyPath := filepath.Join(privateDir, "ca.key.pem")
	certPath := filepath.Join(certsDir, "ca.cert.pem")
	policyPath := filepath.Join(outDir, "policy.txt")

	// Проверка на перезапись (force)
	if !force {
		if _, err := os.Stat(keyPath); err == nil {
			return fmt.Errorf("file %s already exists, use force to overwrite", keyPath)
		}
	}

	// Создание директорий
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		return err
	}
	// 0700 для приватной директории
	if err := os.MkdirAll(privateDir, 0700); err != nil {
		return err
	}

	slog.Info("Generating private key...", "type", strings.ToUpper(keyType), "size", keySize)
	var privateKey crypto.Signer
	if keyType == "rsa" {
		privateKey, err = cryptoutils.GenerateRSAKey()
	} else {
		privateKey, err = cryptoutils.GenerateECCKey()
	}
	if err != nil {
		return fmt.Errorf("key generation failed: %w", err)
	}
	slog.Info("Key generation completed.")

	slog.Info("Creating self-signed certificate...")
	cert, err := certificates.CreateSelfSignedCert(subject, privateKey, validityDays, keyType)
	if err != nil {
		return fmt.Errorf("certificate creation failed: %w", err)
	}
	slog.Info("Certificate created.")

	// Шифрование и сохранение ключа (с правами 0600)
	keyPem, err := cryptoutils.EncryptPrivateKey(privateKey, passphrase)
	if err != nil {
		return fmt.Errorf("key encryption failed: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPem, 0600); err != nil {
		return err
	}
	slog.Info("Private key saved", "path", keyPath)

	// Сохранение сертификата
	certPemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	certPem := pem.EncodeToMemory(certPemBlock)
	if err := os.WriteFile(certPath, certPem, 0644); err != nil {
		return err
	}
	slog.Info("Certificate saved", "path", certPath)

	// Генерация policy.txt
	policyContent := fmt.Sprintf("Certificate Policy Document for MicroPKI Root CA\n"+
		"CA Name: %s\n"+
		"Certificate Serial Number: 0x%x\n"+
		"Validity Period: %s to %s\n"+
		"Key Algorithm: %s %d\n"+
		"Purpose: Root CA for MicroPKI demonstration\n",
		subject, cert.SerialNumber,
		cert.NotBefore.Format("2006-01-02 15:04:05"),
		cert.NotAfter.Format("2006-01-02 15:04:05"),
		strings.ToUpper(keyType), keySize)

	if err := os.WriteFile(policyPath, []byte(policyContent), 0644); err != nil {
		return err
	}
	slog.Info("Policy document saved", "path", policyPath)

	return nil
}
