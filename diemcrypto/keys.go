package diemcrypto

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// Key material is distributed out of band, as PEM files in one directory:
// <id>.key holds replica id's private key, <id>.pub its public key and <id>.crt
// its TLS certificate. This is the smallest thing that lets a cluster start;
// it is not a key management story, and the report says so.

// WriteKeys writes every replica's key pair and certificate into dir as PEM.
func WriteKeys(dir string, privs map[uint32]*ecdsa.PrivateKey) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	certs, err := Certificates(privs)
	if err != nil {
		return err
	}
	for id, key := range privs {
		if err := writePEM(filepath.Join(dir, fmt.Sprintf("%d.crt", id)), "CERTIFICATE", certs[id], 0o644); err != nil {
			return err
		}
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return fmt.Errorf("replica %d private key: %w", id, err)
		}
		if err := writePEM(filepath.Join(dir, fmt.Sprintf("%d.key", id)), "EC PRIVATE KEY", der, 0o600); err != nil {
			return err
		}
		der, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			return fmt.Errorf("replica %d public key: %w", id, err)
		}
		if err := writePEM(filepath.Join(dir, fmt.Sprintf("%d.pub", id)), "PUBLIC KEY", der, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// ReadKeys reads replica id's private key and every replica's public key from
// dir. The public keys found there define the replica set, and so the quorum.
func ReadKeys(dir string, id uint32) (*ecdsa.PrivateKey, map[uint32]*ecdsa.PublicKey, error) {
	der, err := readPEM(filepath.Join(dir, fmt.Sprintf("%d.key", id)), "EC PRIVATE KEY")
	if err != nil {
		return nil, nil, err
	}
	priv, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, nil, fmt.Errorf("replica %d private key: %w", id, err)
	}
	pubs, err := ReadPublicKeys(dir)
	if err != nil {
		return nil, nil, err
	}
	return priv, pubs, nil
}

// ReadPublicKeys reads every replica's public key from dir. They define the
// replica set, and so the quorum.
func ReadPublicKeys(dir string) (map[uint32]*ecdsa.PublicKey, error) {
	names, err := filepath.Glob(filepath.Join(dir, "*.pub"))
	if err != nil {
		return nil, err
	}
	pubs := make(map[uint32]*ecdsa.PublicKey, len(names))
	for _, name := range names {
		base := filepath.Base(name)
		n, err := strconv.ParseUint(base[:len(base)-len(".pub")], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("public key %q: name is not a replica ID", base)
		}
		der, err := readPEM(name, "PUBLIC KEY")
		if err != nil {
			return nil, err
		}
		key, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", base, err)
		}
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%s: not an ECDSA public key", base)
		}
		pubs[uint32(n)] = pub
	}
	// The public keys found here define the replica set, and so the quorum
	// and the leader rotation. They must therefore be exactly 1..n: a stale
	// <id>.pub left in the directory would otherwise change both, silently,
	// and only on the replicas that can see the file.
	if len(pubs) == 0 {
		return nil, fmt.Errorf("no public keys in %s", dir)
	}
	for i := uint32(1); int(i) <= len(pubs); i++ {
		if pubs[i] == nil {
			return nil, fmt.Errorf("%s holds %d public keys but not %d.pub: they must be 1..%d", dir, len(pubs), i, len(pubs))
		}
	}
	return pubs, nil
}

// ReadCerts reads the certificates of replicas 1..n from dir.
func ReadCerts(dir string, n int) (map[uint32][]byte, error) {
	certs := make(map[uint32][]byte, n)
	for id := uint32(1); int(id) <= n; id++ {
		der, err := readPEM(filepath.Join(dir, fmt.Sprintf("%d.crt", id)), "CERTIFICATE")
		if err != nil {
			return nil, err
		}
		certs[id] = der
	}
	return certs, nil
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	b := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, b, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func readPEM(path, blockType string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != blockType {
		return nil, fmt.Errorf("%s: not a %s PEM block", path, blockType)
	}
	return block.Bytes, nil
}
