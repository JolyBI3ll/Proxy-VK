package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"time"
)

func GenerateCertificate(domain string, caCert tls.Certificate) (tls.Certificate, error) {
	caX509Cert, err := getX509Cert(caCert)
	if err != nil {
		return tls.Certificate{}, err
	}

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: domain,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{domain},
		CRLDistributionPoints: []string{"http://127.0.0.1:8080/crl.pem"},
	}

	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		&template,
		caX509Cert,
		&privKey.PublicKey,
		caCert.PrivateKey,
	)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})

	return tls.X509KeyPair(certPEM, keyPEM)
}

func getX509Cert(tlsCert tls.Certificate) (*x509.Certificate, error) {
	if len(tlsCert.Certificate) == 0 {
		return nil, errors.New("no certificates found")
	}
	return x509.ParseCertificate(tlsCert.Certificate[0])
}
