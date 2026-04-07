package certificates

import (
	"crypto/x509"
	"testing"

	"micropki/internal/cryptoutils"
)

func TestParseDNSlash(t *testing.T) {
	dn := ParseDN("/CN=Root CA/O=Demo/C=US")
	if dn.CommonName != "Root CA" {
		t.Errorf("Expected CN=Root CA, got %s", dn.CommonName)
	}
	if len(dn.Organization) == 0 || dn.Organization[0] != "Demo" {
		t.Errorf("Expected O=Demo")
	}
	if len(dn.Country) == 0 || dn.Country[0] != "US" {
		t.Errorf("Expected C=US")
	}
}

func TestParseDNComma(t *testing.T) {
	dn := ParseDN("CN=Root CA,O=Demo,C=US")
	if dn.CommonName != "Root CA" || len(dn.Organization) == 0 || dn.Organization[0] != "Demo" {
		t.Errorf("DN parsing failed for comma separated format")
	}
}

func TestSerialNumber(t *testing.T) {
	sn, err := GenerateSerialNumber()
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}
	if sn.Sign() <= 0 {
		t.Errorf("Serial number must be positive")
	}
	if sn.BitLen() > 152 {
		t.Errorf("Serial number exceeds 152 bits, got %d", sn.BitLen())
	}
}

func TestCreateSelfSignedRSA(t *testing.T) {
	key, _ := cryptoutils.GenerateRSAKey()
	cert, err := CreateSelfSignedCert("CN=Test CA", key, 365, "rsa")
	if err != nil {
		t.Fatalf("Failed to create cert: %v", err)
	}

	if cert.Subject.CommonName != cert.Issuer.CommonName {
		t.Errorf("Subject and Issuer should be identical for self-signed cert")
	}
	if !cert.IsCA {
		t.Errorf("Expected CA=True")
	}
	if cert.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) == 0 {
		t.Errorf("Expected KeyUsage to include CertSign and CRLSign")
	}
}

func TestCreateSelfSignedECC(t *testing.T) {
	key, _ := cryptoutils.GenerateECCKey()
	cert, err := CreateSelfSignedCert("CN=Test ECC CA", key, 365, "ecc")
	if err != nil {
		t.Fatalf("Failed to create cert: %v", err)
	}

	if cert.SignatureAlgorithm != x509.ECDSAWithSHA384 {
		t.Errorf("Expected signature algorithm ECDSAWithSHA384, got %v", cert.SignatureAlgorithm)
	}
}
