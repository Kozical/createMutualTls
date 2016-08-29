package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

func main() {
	org := "ca"

	var names []string
	buf := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("Enter the FQDN of a host (hit <enter> to finish): ")
		data, _, _ := buf.ReadLine()
		if len(data) == 0 {
			break
		}
		names = append(names, string(data))
	}

	ca := newParentCertificate("ca", org)

	parentPriv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate private key for ca -> %s\n", err)
		return
	}
	parentDer, err := x509.CreateCertificate(rand.Reader, ca, ca, &parentPriv.PublicKey, parentPriv)
	if err != nil {
		fmt.Printf("Failed to create certificate for ca -> %s\n", err)
		return
	}
	if err := writeCertificateFiles("ca", parentDer, []byte{}, parentPriv); err != nil {
		fmt.Printf("Failed to write certificate files for ca -> %s", err)
	}

	fmt.Println("Wrote CA certificate")

	for i, n := range names {
		c := newChildCertificate(n, org, i+2)

		priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			fmt.Printf("Failed to generate private key for %s -> %s\n", n, err)
			continue
		}

		der, err := x509.CreateCertificate(rand.Reader, c, ca, &priv.PublicKey, parentPriv)
		if err != nil {
			fmt.Printf("Failed to create certificate for %s -> %s\n", n, err)
			continue
		}

		if err := writeCertificateFiles(n, der, parentDer, priv); err != nil {
			fmt.Printf("Failed to write certificate files for %s -> %s", n, err)
		}

		fmt.Printf("Wrote certificate for %s\n", n)
	}
}

func newParentCertificate(name string, org string) *x509.Certificate {
	now := time.Now()
	return &x509.Certificate{
		SerialNumber: big.NewInt(1),
		SubjectKeyId: []byte{1},
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{org},
		},
		SignatureAlgorithm:    x509.ECDSAWithSHA512,
		PublicKeyAlgorithm:    x509.ECDSA,
		NotBefore:             now.UTC(),
		NotAfter:              now.AddDate(0, 0, 1825).UTC(),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA: true,
	}
}

func newChildCertificate(name string, org string, id int) *x509.Certificate {
	now := time.Now()
	return &x509.Certificate{
		SerialNumber: big.NewInt(int64(id)),
		SubjectKeyId: []byte{byte(id)},
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{org},
		},
		SignatureAlgorithm: x509.ECDSAWithSHA512,
		PublicKeyAlgorithm: x509.ECDSA,
		NotBefore:          now.UTC(),
		NotAfter:           now.AddDate(0, 0, 1825).UTC(),
		KeyUsage:           x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		IsCA:               false,
	}
}

func writeCertificateFiles(name string, der []byte, parentDer []byte, priv *ecdsa.PrivateKey) error {
	certFile, err := os.Create(fmt.Sprintf("%s.crt", name))
	if err != nil {
		return fmt.Errorf("Failed to create %s.crt file -> %s", name, err)
	}
	defer certFile.Close()

	keyFile, err := os.Create(fmt.Sprintf("%s.key", name))
	if err != nil {
		return fmt.Errorf("Failed to create %s.key file -> %s", name, err)
	}
	defer keyFile.Close()

	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return fmt.Errorf("Failed to write PEM block to %s.crt -> %s", name, err)
	}
	if len(parentDer) != 0 {
		if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: parentDer}); err != nil {
			return fmt.Errorf("Failed to write CA PEM block to %s.crt -> %s", name, err)
		}
	}

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("Failed to marshal elliptic curve private key -> %s", err)
	}

	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("Failed to write PEM block to %s.key -> %s", name, err)
	}
	return nil
}
