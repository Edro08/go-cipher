package rsa

import (
	"GoCipher/internal/cipher"
	"GoCipher/kit/constants"
	"GoCipher/kit/errorsCatalog"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"github.com/edro08/go-utils/config"
	"github.com/edro08/go-utils/logger"
	"strings"
)

const (
	titleDecrypt = "RSA CIPHER DECRYPT"
	tileEncrypt  = "RSA CIPHER ENCRYPT"
	typeRSA      = "RSA"

	ckType       = "profiles.$profile.type"
	ckPublicKey  = "profiles.$profile.keys.public"
	ckPrivateKey = "profiles.$profile.keys.private"

	repProfile = "$profile"
)

type Cipher struct {
	config config.IConfig
	logger logger.ILogger
	next   cipher.IService
}

func NewRSA(config config.IConfig, logger logger.ILogger, next cipher.IService) *Cipher {
	return &Cipher{
		config: config,
		logger: logger,
		next:   next,
	}
}

// Decrypt decrypts a cipher text using a rsa private key.
//
// Parameters:
// - ctx: The context for the operation.
// - req: The cipher request containing the cipher type and value.
//
// Returns:
// - cipher.Response: The decrypted cipher response.
// - error: An error if the decryption fails.
//
// The function attempts to decrypt the cipher text using the provided rsa private key.
// It first parses the rsa private key from the PEM string, then decodes the cipher text
// from Base64, and finally decrypts the cipher text using the private key.
// If any step fails, an error is returned.
// ------------------------------------------------------------------------------------------
func (c *Cipher) Decrypt(ctx context.Context, req cipher.Request) (cipher.Response, error) {
	typeProfile := c.config.GetString(strings.Replace(ckType, repProfile, req.Profile, 1))
	if !strings.EqualFold(typeProfile, typeRSA) {
		c.logger.Info(titleDecrypt, "status", "next", "type", typeProfile, constants.ProcessID, ctx.Value(constants.ProcessID))
		return c.next.Decrypt(ctx, req)
	}

	c.logger.Info(titleDecrypt, "status", "initializing decrypt", constants.ProcessID, ctx.Value(constants.ProcessID))

	// Parse rsa private key from PEM string
	privateKeyStr := c.config.GetString(strings.Replace(ckPrivateKey, repProfile, req.Profile, 1))
	privateKey, err := c.ParseRSAPrivateKeyFromPEM(privateKeyStr)
	if err != nil {
		c.logger.Error(titleDecrypt, "status", "failed to parse rsa private key", "error", err.Error(), constants.ProcessID, ctx.Value(constants.ProcessID))
		return cipher.Response{}, err
	}

	// Decode Base64 to bytes
	cipherBytes, err := base64.StdEncoding.DecodeString(req.Value)
	if err != nil {
		errWrap := fmt.Errorf("%w: %v", errorsCatalog.ErrDecodeBase64, err)
		c.logger.Error(titleDecrypt, "status", "failed to decode base64", "error", errWrap.Error(), constants.ProcessID, ctx.Value(constants.ProcessID))
		return cipher.Response{}, errWrap
	}

	// Decrypt using rsa
	decryptedBytes, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherBytes)
	if err != nil {
		errWrap := fmt.Errorf("%w: %v", errorsCatalog.ErrDecryptFailed, err)
		c.logger.Error(titleDecrypt, "status", "failed to decrypt rsa", "error", errWrap.Error(), constants.ProcessID, ctx.Value(constants.ProcessID))
		return cipher.Response{}, errWrap
	}

	c.logger.Info(titleDecrypt, "status", "decrypted", constants.ProcessID, ctx.Value(constants.ProcessID))
	return cipher.Response{
		ProcessID: ctx.Value(constants.ProcessID).(string),
		Profile:   req.Profile,
		Value:     string(decryptedBytes),
	}, nil
}

// Encrypt encrypts the given text using an RSA public key in PEM format.
//
// Parameters:
// - ctx: The context for the operation.
// - req: The cipher request containing the cipher type and value.
//
// Returns:
// - cipher.Response: The decrypted cipher response.
// - error: An error if the encryption fails.
//
// The function first parses the RSA public key from the PEM string, then encodes the plain text
// to bytes, and finally encrypts the bytes using the public key.
// If any step fails, an error is returned.
// ------------------------------------------------------------------------------------------
func (c *Cipher) Encrypt(ctx context.Context, req cipher.Request) (cipher.Response, error) {
	typeProfile := c.config.GetString(strings.Replace(ckType, repProfile, req.Profile, 1))
	if !strings.EqualFold(typeProfile, typeRSA) {
		c.logger.Info(titleDecrypt, "status", "next", "type", typeProfile, constants.ProcessID, ctx.Value(constants.ProcessID))
		return c.next.Decrypt(ctx, req)
	}

	c.logger.Info(tileEncrypt, "status", "initializing encrypt", constants.ProcessID, ctx.Value(constants.ProcessID))

	// Parse rsa public key from PEM string
	publicKeyStr := c.config.GetString(strings.Replace(ckPublicKey, repProfile, req.Profile, 1))
	publicKey, err := c.ParseRSAPublicKeyFromPEM(publicKeyStr)
	if err != nil {
		c.logger.Error(tileEncrypt, "status", "failed to parse rsa public key", "error", err.Error(), constants.ProcessID, ctx.Value(constants.ProcessID))
		return cipher.Response{}, err
	}

	// Decode string to bytes
	cipherBytes := []byte(req.Value)

	// Encrypt the cipherBytes with rsa using the public key
	encryptedBytes, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, cipherBytes)
	if err != nil {
		errWrap := fmt.Errorf("%w: %v", errorsCatalog.ErrEncryptFailed, err)
		c.logger.Error(titleDecrypt, "status", "failed to encrypt rsa", "error", errWrap.Error(), constants.ProcessID, ctx.Value(constants.ProcessID))
		return cipher.Response{}, errWrap
	}

	c.logger.Info(titleDecrypt, "status", "encrypted", constants.ProcessID, ctx.Value(constants.ProcessID))
	return cipher.Response{
		ProcessID: ctx.Value(constants.ProcessID).(string),
		Profile:   req.Profile,
		Value:     base64.StdEncoding.EncodeToString(encryptedBytes),
	}, nil
}
