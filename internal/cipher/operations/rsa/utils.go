package rsa

import (
	"GoCipher/kit/errorsCatalog"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// ParseRSAPrivateKeyFromPEM parses a rsa private key from a PEM-encoded string.
//
// Parameters:
// - privateKeyStr: The rsa private key in PEM format as a string.
//
// Returns:
// - A pointer to a rsa.PrivateKey if the parsing is successful.
// - An error if there is an issue decoding the PEM block or parsing the private key.
//
// The function decodes the PEM block from the input string and attempts to parse the key
// as a PKCS1-formatted rsa private key. It will return an error if the PEM block is invalid
// or if the key is not in the correct format.
// ------------------------------------------------------------------------------------------
func (c *Cipher) ParseRSAPrivateKeyFromPEM(privateKeyStr string) (*rsa.PrivateKey, error) {
	if privateKeyStr == "" {
		return nil, errorsCatalog.ErrPrivateKeyNotFound
	}

	// Decode the PEM string
	block, _ := pem.Decode([]byte(privateKeyStr))
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errorsCatalog.ErrDecodePEMBlockPrivate
	}

	// Parse the private key
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errorsCatalog.ErrParsePrivateKey, err)
	}

	return privateKey, nil
}

// ------------------------------------------------------------------------------------------
// ------------------------------------------------------------------------------------------

// ParseRSAPublicKeyFromPEM parses an RSA public key from a PEM-encoded string.
//
// Parameters:
//   - publicKeyStr: The RSA public key in PEM format as a string.
//     It must be a valid PEM block containing a public key.
//
// Returns:
//   - A pointer to a rsa.PublicKey if the parsing is successful.
//   - An error if the public key is not found, the PEM block is invalid, or
//     the parsing process fails.
//
// The function decodes the provided PEM string to extract the public key,
// verifies that the PEM block type is "PUBLIC KEY", and then attempts to parse it
// using x509.ParsePKIXPublicKey. If successful, it returns the parsed RSA public key;
// otherwise, it returns a relevant error.
// ------------------------------------------------------------------------------------------
func (c *Cipher) ParseRSAPublicKeyFromPEM(publicKeyStr string) (*rsa.PublicKey, error) {
	if publicKeyStr == "" {
		return nil, errorsCatalog.ErrPublicKeyNotFound
	}

	// Decode the PEM string
	block, _ := pem.Decode([]byte(publicKeyStr))
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errorsCatalog.ErrDecodePEMBlockPublic
	}

	// Parse the public key
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errorsCatalog.ErrParsePublicKey, err)
	}

	// Assert the type of public key to *rsa.PublicKey
	publicKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w", errorsCatalog.ErrParsePublicKey)
	}

	return publicKey, nil
}
