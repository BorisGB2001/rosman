// Package pki generates a CA and issues RouterOS api-ssl server certificates
// signed by it, using the standard library's crypto/x509.
package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// GenerateCA creates a self-signed CA (RSA-2048, 10 years) and returns the
// certificate and private key as PEM.
func GenerateCA(commonName string) (certPEM, keyPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true, // issues leaves only
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM, nil
}

// ParseCA validates a CA certificate+key pair (both PEM) and returns them parsed.
func ParseCA(certPEM, keyPEM []byte) (*x509.Certificate, any, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, nil, fmt.Errorf("CA certificate is not valid PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA certificate: %w", err)
	}
	if !cert.IsCA {
		return nil, nil, fmt.Errorf("the certificate is not a CA (BasicConstraints CA:FALSE)")
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, nil, err
	}
	return cert, key, nil
}

func parseKey(keyPEM []byte) (any, error) {
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, fmt.Errorf("private key is not valid PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(kb.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS8PrivateKey(kb.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(kb.Bytes); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("unsupported private key format")
}

// IssueServerCert issues a TLS server certificate signed by the CA.
// days is capped so the leaf never outlives the CA. Returns cert PEM, key PEM,
// the hex SHA-256 of the leaf DER (the api-ssl pin) and its expiry.
func IssueServerCert(caCertPEM, caKeyPEM []byte, commonName string, ips []net.IP, dns []string, days int) (certPEM, keyPEM []byte, fingerprint string, expiry time.Time, err error) {
	caCert, caKey, err := ParseCA(caCertPEM, caKeyPEM)
	if err != nil {
		return nil, nil, "", time.Time{}, err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, "", time.Time{}, err
	}
	notAfter := time.Now().AddDate(0, 0, days)
	if notAfter.After(caCert.NotAfter) {
		notAfter = caCert.NotAfter
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  ips,
		DNSNames:     dns,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, "", time.Time{}, err
	}
	sum := sha256.Sum256(der)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM, hex.EncodeToString(sum[:]), notAfter, nil
}

// CASubject returns the CA certificate's common name (for display).
func CASubject(certPEM []byte) string {
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return ""
	}
	c, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return ""
	}
	return c.Subject.CommonName
}
