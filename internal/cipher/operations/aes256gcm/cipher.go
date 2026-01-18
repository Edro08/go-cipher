package aes256gcm

import (
	internalCipher "GoCipher/internal/cipher"
	"GoCipher/kit/constants"
	"GoCipher/kit/errorsCatalog"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"github.com/edro08/go-utils/config"
	"github.com/edro08/go-utils/logger"
)

const (
	titleDecrypt  = "AES256GCM CIPHER DECRYPT"
	titleEncrypt  = "AES256GCM CIPHER ENCRYPT"
	typeAES256GCM = "AES256-GCM"

	ckType   = "profiles.$profile.type"
	ckSecret = "profiles.$profile.keys.secret"

	repProfile = "$profile"
)

type Cipher struct {
	config config.IConfig
	logger logger.ILogger
	next   internalCipher.IService
}

func NewAES256GCM(config config.IConfig, logger logger.ILogger, next internalCipher.IService) *Cipher {
	return &Cipher{
		config: config,
		logger: logger,
		next:   next,
	}
}

func (c *Cipher) Decrypt(ctx context.Context, req internalCipher.Request) (internalCipher.Response, error) {
	typeProfile := c.config.GetString(strings.Replace(ckType, repProfile, req.Profile, 1))
	if !strings.EqualFold(typeProfile, typeAES256GCM) {
		c.logger.Info(titleDecrypt, "status", "next", "type", typeProfile, constants.ProcessID, ctx.Value(constants.ProcessID))
		return c.next.Decrypt(ctx, req)
	}

	c.logger.Info(titleDecrypt, "status", "initializing decrypt", constants.ProcessID, ctx.Value(constants.ProcessID))

	secret := c.config.GetString(strings.Replace(ckSecret, repProfile, req.Profile, 1))

	// Decode Base64
	cipherBytes, err := base64.StdEncoding.DecodeString(req.Value)
	if err != nil {
		errWrap := fmt.Errorf("%w: %v", errorsCatalog.ErrDecodeBase64, err)
		c.logger.Error(titleDecrypt, "status", "failed to decode base64", "error", errWrap.Error(), constants.ProcessID, ctx.Value(constants.ProcessID))
		return internalCipher.Response{}, errWrap
	}

	block, err := aes.NewCipher([]byte(secret))
	if err != nil {
		errWrap := fmt.Errorf("%w: %v", errorsCatalog.ErrCreateCipherBlock, err)
		c.logger.Error(titleDecrypt, "status", "failed to create cipher block", "error", errWrap.Error(), constants.ProcessID, ctx.Value(constants.ProcessID))
		return internalCipher.Response{}, errWrap
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		errWrap := fmt.Errorf("%w: %v", errorsCatalog.ErrCreateGCM, err)
		c.logger.Error(titleDecrypt, "status", "failed to create GCM", "error", errWrap.Error(), constants.ProcessID, ctx.Value(constants.ProcessID))
		return internalCipher.Response{}, errWrap
	}

	nonceSize := aesGCM.NonceSize()
	if len(cipherBytes) < nonceSize {
		errWrap := fmt.Errorf("%w: ciphertext too short", errorsCatalog.ErrDecryptFailed)
		c.logger.Error(titleDecrypt, "status", "ciphertext too short", "error", errWrap.Error(), constants.ProcessID, ctx.Value(constants.ProcessID))
		return internalCipher.Response{}, errWrap
	}

	nonce, ciphertext := cipherBytes[:nonceSize], cipherBytes[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		errWrap := fmt.Errorf("%w: %v", errorsCatalog.ErrDecryptFailed, err)
		c.logger.Error(titleDecrypt, "status", "failed to decrypt", "error", errWrap.Error(), constants.ProcessID, ctx.Value(constants.ProcessID))
		return internalCipher.Response{}, errWrap
	}

	c.logger.Info(titleDecrypt, "status", "decrypted", constants.ProcessID, ctx.Value(constants.ProcessID))
	return internalCipher.Response{
		ProcessID: ctx.Value(constants.ProcessID).(string),
		Profile:   req.Profile,
		Value:     string(plaintext),
	}, nil
}

func (c *Cipher) Encrypt(ctx context.Context, req internalCipher.Request) (internalCipher.Response, error) {
	typeProfile := c.config.GetString(strings.Replace(ckType, repProfile, req.Profile, 1))
	if !strings.EqualFold(typeProfile, typeAES256GCM) {
		c.logger.Info(titleEncrypt, "status", "next", "type", typeProfile, constants.ProcessID, ctx.Value(constants.ProcessID))
		return c.next.Encrypt(ctx, req)
	}

	c.logger.Info(titleEncrypt, "status", "initializing encrypt", constants.ProcessID, ctx.Value(constants.ProcessID))

	secret := c.config.GetString(strings.Replace(ckSecret, repProfile, req.Profile, 1))

	block, err := aes.NewCipher([]byte(secret))
	if err != nil {
		errWrap := fmt.Errorf("%w: %v", errorsCatalog.ErrCreateCipherBlock, err)
		c.logger.Error(titleEncrypt, "status", "failed to create cipher block", "error", errWrap.Error(), constants.ProcessID, ctx.Value(constants.ProcessID))
		return internalCipher.Response{}, errWrap
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		errWrap := fmt.Errorf("%w: %v", errorsCatalog.ErrCreateGCM, err)
		c.logger.Error(titleEncrypt, "status", "failed to create GCM", "error", errWrap.Error(), constants.ProcessID, ctx.Value(constants.ProcessID))
		return internalCipher.Response{}, errWrap
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		errWrap := fmt.Errorf("%w: %v", errorsCatalog.ErrGenerateNonce, err)
		c.logger.Error(titleEncrypt, "status", "failed to generate nonce", "error", errWrap.Error(), constants.ProcessID, ctx.Value(constants.ProcessID))
		return internalCipher.Response{}, errWrap
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(req.Value), nil)

	c.logger.Info(titleEncrypt, "status", "encrypted", constants.ProcessID, ctx.Value(constants.ProcessID))
	return internalCipher.Response{
		ProcessID: ctx.Value(constants.ProcessID).(string),
		Profile:   req.Profile,
		Value:     base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}
