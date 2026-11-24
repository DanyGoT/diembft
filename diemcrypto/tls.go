package diemcrypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net/url"
	"time"
)

// Each replica presents a self-signed certificate over its signing key, and
// trusts exactly the replicas' certificates: there is no CA that could issue
// another. A certificate names its replica by URI, which is what Gorums checks
// a peer against. All of them also carry the DNS name tlsName, which every
// dialer expects instead of the host it dials, since crypto/tls matches a
// server against DNS and IP names only. Reusing the signing key keeps one key
// per replica; a production deployment would keep them apart.

const tlsName = "diembft"

// TLSIdentity is the URI that replica id's certificate carries.
func TLSIdentity(id uint32) string {
	return fmt.Sprintf("spiffe://diembft/replica/%d", id)
}

// Certificates returns a self-signed DER certificate for each replica in privs.
func Certificates(privs map[uint32]*ecdsa.PrivateKey) (map[uint32][]byte, error) {
	certs := make(map[uint32][]byte, len(privs))
	for id, key := range privs {
		uri, err := url.Parse(TLSIdentity(id))
		if err != nil {
			return nil, err
		}
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return nil, err
		}
		now := time.Now()
		tmpl := &x509.Certificate{
			SerialNumber:          serial,
			URIs:                  []*url.URL{uri},
			DNSNames:              []string{tlsName},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.AddDate(10, 0, 0),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			BasicConstraintsValid: true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			return nil, fmt.Errorf("replica %d certificate: %w", id, err)
		}
		certs[id] = der
	}
	return certs, nil
}

// TLSConfig is replica id's TLS configuration, for its server and its dialer
// alike: it presents certs[id] with key, and accepts a peer only if it
// presents one of certs. A client may connect without a certificate: Gorums
// refuses a stream that claims a replica's ID without that replica's
// certificate, and one that claims none can send no protocol message, since
// each must name its sender. It can still call RequestBlock and Ready, which
// name no sender and only read.
func TLSConfig(id uint32, key *ecdsa.PrivateKey, certs map[uint32][]byte) (*tls.Config, error) {
	if certs[id] == nil {
		return nil, fmt.Errorf("no certificate for replica %d", id)
	}
	c, err := ClientTLSConfig(certs)
	if err != nil {
		return nil, err
	}
	c.Certificates = []tls.Certificate{{Certificate: [][]byte{certs[id]}, PrivateKey: key}}
	c.ClientCAs = c.RootCAs
	c.ClientAuth = tls.VerifyClientCertIfGiven
	return c, nil
}

// ClientTLSConfig is a client's TLS configuration: it trusts exactly the
// replicas' certificates and presents none.
func ClientTLSConfig(certs map[uint32][]byte) (*tls.Config, error) {
	pool := x509.NewCertPool()
	for i, der := range certs {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("replica %d certificate: %w", i, err)
		}
		pool.AddCert(c)
	}
	return &tls.Config{RootCAs: pool, ServerName: tlsName, MinVersion: tls.VersionTLS13}, nil
}
