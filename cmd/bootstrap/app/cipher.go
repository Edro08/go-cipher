package app

import (
	"GoCipher/internal/cipher/operations/aes256cbc"
	"GoCipher/internal/cipher/operations/aes256gcm"
	"GoCipher/internal/cipher/operations/none"
	"GoCipher/internal/cipher/operations/rsa"
	"GoCipher/internal/cipher/platform/handler"
	"net/http"

	"github.com/edro08/go-utils/config"
	"github.com/edro08/go-utils/logger"
	"github.com/gorilla/mux"
)

const (
	ckPathCipherEncrypt = "endpoints.paths.cipher.encrypt"
	ckPathCipherDecrypt = "endpoints.paths.cipher.decrypt"
)

// RunRestApiCipher sets up REST API routes for cipher encryption and decryption
func RunRestApiCipher(router *mux.Router, cfg config.IConfig, logger logger.ILogger) {
	newNone := none.NewNone(cfg, logger)
	newRSA := rsa.NewRSA(cfg, logger, newNone)
	newAES256GCM := aes256gcm.NewAES256GCM(cfg, logger, newRSA)
	newAES256CBC := aes256cbc.NewAES256CBC(cfg, logger, newAES256GCM)
	transport := handler.NewTransport(cfg, newAES256CBC)
	router.HandleFunc(cfg.GetString(ckPathCipherDecrypt), transport.Decrypt).Methods(http.MethodPost)
	router.HandleFunc(cfg.GetString(ckPathCipherEncrypt), transport.Encrypt).Methods(http.MethodPost)
}
