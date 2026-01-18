package aes256cbc

import (
	internalCipher "GoCipher/internal/cipher"
	"GoCipher/kit/constants"
	"GoCipher/kit/errorsCatalog"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/edro08/go-utils/config"
	"github.com/edro08/go-utils/logger"
)

const (
	titleDecrypt  = "AES256CBC CIPHER DECRYPT"
	titleEncrypt  = "AES256CBC CIPHER ENCRYPT"
	typeAES256CBC = "AES256-CBC"

	ckType   = "profiles.$profile.type"
	ckSecret = "profiles.$profile.keys.secret"
	ckIV     = "profiles.$profile.keys.iv"

	repProfile = "$profile"
)

type Cipher struct {
	config config.IConfig
	logger logger.ILogger
	next   internalCipher.IService
}

func NewAES256CBC(config config.IConfig, logger logger.ILogger, next internalCipher.IService) *Cipher {
	return &Cipher{
		config: config,
		logger: logger,
		next:   next,
	}
}

func (c *Cipher) Decrypt(ctx context.Context, req internalCipher.Request) (internalCipher.Response, error) {
	typeProfile := c.config.GetString(strings.Replace(ckType, repProfile, req.Profile, 1))
	if !strings.EqualFold(typeProfile, typeAES256CBC) {
		c.logger.Info(titleDecrypt, "status", "next", "type", typeProfile, constants.ProcessID, ctx.Value(constants.ProcessID))
		return c.next.Decrypt(ctx, req)
	}

	c.logger.Info(titleDecrypt, "status", "initializing decrypt", constants.ProcessID, ctx.Value(constants.ProcessID))

	secret := c.config.GetString(strings.Replace(ckSecret, repProfile, req.Profile, 1))
	iv := c.config.GetString(strings.Replace(ckIV, repProfile, req.Profile, 1))

	// Decode Base64
	cipherBytes, err := base64.StdEncoding.DecodeString(req.Value)
	if err != nil {
		errWrap := fmt.Errorf("%w: %v", errorsCatalog.ErrDecodeBase64, err)
		c.logger.Error(titleDecrypt, "status", "failed to decode base64", "value", req.Value, "error", errWrap.Error(), constants.ProcessID, ctx.Value(constants.ProcessID))
		return internalCipher.Response{}, errWrap
	}

	block, err := aes.NewCipher([]byte(secret))
	if err != nil {
		errWrap := fmt.Errorf("%w: %v", errorsCatalog.ErrCreateCipherBlock, err)
		c.logger.Error(titleDecrypt, "status", "failed to create cipher block", "error", errWrap.Error(), constants.ProcessID, ctx.Value(constants.ProcessID))
		return internalCipher.Response{}, errWrap
	}

	if len(cipherBytes)%aes.BlockSize != 0 {
		errWrap := fmt.Errorf("%w: ciphertext is not a multiple of the block size", errorsCatalog.ErrDecryptFailed)
		c.logger.Error(titleDecrypt, "status", "invalid ciphertext length", "error", errWrap.Error(), constants.ProcessID, ctx.Value(constants.ProcessID))
		return internalCipher.Response{}, errWrap
	}

	mode := cipher.NewCBCDecrypter(block, []byte(iv))
	mode.CryptBlocks(cipherBytes, cipherBytes)

	// Unpad
	cipherBytes, err = pkcs7Unpadding(cipherBytes)
	if err != nil {
		errWrap := fmt.Errorf("%w: %v", errorsCatalog.ErrDecryptFailed, err)
		c.logger.Error(titleDecrypt, "status", "failed to unpad", "error", errWrap.Error(), constants.ProcessID, ctx.Value(constants.ProcessID))
		return internalCipher.Response{}, errWrap
	}

	c.logger.Info(titleDecrypt, "status", "decrypted", constants.ProcessID, ctx.Value(constants.ProcessID))
	return internalCipher.Response{
		ProcessID: ctx.Value(constants.ProcessID).(string),
		Profile:   req.Profile,
		Value:     string(cipherBytes),
	}, nil
}

func (c *Cipher) Encrypt(ctx context.Context, req internalCipher.Request) (internalCipher.Response, error) {
	typeProfile := c.config.GetString(strings.Replace(ckType, repProfile, req.Profile, 1))
	if !strings.EqualFold(typeProfile, typeAES256CBC) {
		c.logger.Info(titleEncrypt, "status", "next", "type", typeProfile, constants.ProcessID, ctx.Value(constants.ProcessID))
		return c.next.Encrypt(ctx, req)
	}

	c.logger.Info(titleEncrypt, "status", "initializing encrypt", constants.ProcessID, ctx.Value(constants.ProcessID))

	secret := c.config.GetString(strings.Replace(ckSecret, repProfile, req.Profile, 1))
	iv := c.config.GetString(strings.Replace(ckIV, repProfile, req.Profile, 1))

	block, err := aes.NewCipher([]byte(secret))
	if err != nil {
		errWrap := fmt.Errorf("%w: %v", errorsCatalog.ErrCreateCipherBlock, err)
		c.logger.Error(titleEncrypt, "status", "failed to create cipher block", "error", errWrap.Error(), constants.ProcessID, ctx.Value(constants.ProcessID))
		return internalCipher.Response{}, errWrap
	}

	plainBytes := []byte(req.Value)
	plainBytes = pkcs7Padding(plainBytes, aes.BlockSize)

	cipherBytes := make([]byte, len(plainBytes))
	mode := cipher.NewCBCEncrypter(block, []byte(iv))
	mode.CryptBlocks(cipherBytes, plainBytes)

	c.logger.Info(titleEncrypt, "status", "encrypted", constants.ProcessID, ctx.Value(constants.ProcessID))
	return internalCipher.Response{
		ProcessID: ctx.Value(constants.ProcessID).(string),
		Profile:   req.Profile,
		Value:     base64.StdEncoding.EncodeToString(cipherBytes),
	}, nil
}

func pkcs7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func pkcs7Unpadding(origData []byte) ([]byte, error) {
	length := len(origData)
	if length == 0 {
		return nil, fmt.Errorf("invalid padding size")
	}
	unpadding := int(origData[length-1])
	if length < unpadding {
		return nil, fmt.Errorf("invalid padding size")
	}
	return origData[:(length - unpadding)], nil
}
