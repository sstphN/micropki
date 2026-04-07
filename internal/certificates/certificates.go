package certificates

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"time"
)

// ParseDN конвертирует строку DN в pkix.Name.
func ParseDN(dnString string) pkix.Name {
	dn := pkix.Name{}
	dnString = strings.TrimSpace(dnString)
	var parts []string

	if strings.HasPrefix(dnString, "/") {
		parts = strings.Split(dnString, "/")[1:]
	} else {
		parts = strings.Split(dnString, ",")
	}

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, "=") {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		key := strings.ToUpper(strings.TrimSpace(kv[0]))
		value := strings.TrimSpace(kv[1])

		switch key {
		case "CN":
			dn.CommonName = value
		case "O":
			dn.Organization = append(dn.Organization, value)
		case "OU":
			dn.OrganizationalUnit = append(dn.OrganizationalUnit, value)
		case "C":
			dn.Country = append(dn.Country, value)
		case "ST":
			dn.Province = append(dn.Province, value)
		case "L":
			dn.Locality = append(dn.Locality, value)
		case "STREET":
			dn.StreetAddress = append(dn.StreetAddress, value)
		case "EMAIL":
			// OID для email: 1.2.840.113549.1.9.1
			dn.ExtraNames = append(dn.ExtraNames, pkix.AttributeTypeAndValue{
				Type:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1},
				Value: value,
			})
		}
	}
	return dn
}

// GenerateSerialNumber генерирует случайный 152-битный серийный номер (19 байт).
func GenerateSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 152) // 2^152
	return rand.Int(rand.Reader, limit)
}

// CreateSelfSignedCert создает самоподписанный X.509 сертификат.
func CreateSelfSignedCert(subjectDN string, privateKey crypto.Signer, validityDays int, keyType string) (*x509.Certificate, error) {
	subject := ParseDN(subjectDN)
	serialNumber, err := GenerateSerialNumber()
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	notAfter := now.Add(time.Duration(validityDays) * 24 * time.Hour)

	// Вычисляем SubjectKeyIdentifier (SHA-1 от публичного ключа, стандартный метод)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return nil, err
	}
	skiHash := sha1.Sum(pubKeyBytes)

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             now,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId:          skiHash[:],
		AuthorityKeyId:        skiHash[:], // Совпадает со SKI, так как сертификат самоподписанный
	}

	if keyType == "rsa" {
		template.SignatureAlgorithm = x509.SHA256WithRSA
	} else {
		template.SignatureAlgorithm = x509.ECDSAWithSHA384
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, privateKey.Public(), privateKey)
	if err != nil {
		return nil, err
	}

	// Парсим DER-байты обратно в структуру x509.Certificate
	return x509.ParseCertificate(derBytes)
}
