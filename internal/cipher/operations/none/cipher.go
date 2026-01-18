package none

import (
	"GoCipher/internal/cipher"
	"GoCipher/kit/constants"
	"GoCipher/kit/errorsCatalog"
	"context"
	"github.com/edro08/go-utils/config"
	"github.com/edro08/go-utils/logger"
)

const (
	titleDecrypt = "NONE CIPHER DECRYPT"
	tileEncrypt  = "NONE CIPHER ENCRYPT"
)

type Cipher struct {
	config config.IConfig
	logger logger.ILogger
}

func NewNone(config config.IConfig, logger logger.ILogger) *Cipher {
	return &Cipher{
		config: config,
		logger: logger,
	}
}

func (c *Cipher) Encrypt(ctx context.Context, req cipher.Request) (cipher.Response, error) {
	c.logger.Warn(tileEncrypt, "status", errorsCatalog.ErrNotImplemented, constants.ProcessID, ctx.Value(constants.ProcessID))
	return cipher.Response{}, errorsCatalog.ErrNotImplemented
}

func (c *Cipher) Decrypt(ctx context.Context, req cipher.Request) (cipher.Response, error) {
	c.logger.Warn(titleDecrypt, "status", errorsCatalog.ErrNotImplemented, constants.ProcessID, ctx.Value(constants.ProcessID))
	return cipher.Response{}, errorsCatalog.ErrNotImplemented
}
