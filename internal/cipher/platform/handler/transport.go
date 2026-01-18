package handler

import (
	"GoCipher/internal/cipher"
	"GoCipher/kit/constants"
	"GoCipher/kit/errorsCatalog"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/edro08/go-utils/config"
	"github.com/google/uuid"
)

type Transport struct {
	config  config.IConfig
	service cipher.IService
}

func NewTransport(config config.IConfig, service cipher.IService) *Transport {
	return &Transport{
		config:  config,
		service: service,
	}
}

// Encrypt handles the encryption of plaintext.
//
// @Summary Encrypt
// @Description Encrypts the provided plaintext and returns the ciphertext.
// @Tags Cipher
// @Accept json
// @Produce json
// @Param Request body cipher.Request true "Plaintext to encrypt"
// @Success 200 {object} cipher.Response "Encrypted text response"
// @Failure 400 {object} cipher.Response "Bad request"
// @Failure 500 {object} cipher.Response "Internal server error"
// @Router /api/cipher/encrypt [POST]
func (t *Transport) Encrypt(w http.ResponseWriter, r *http.Request) {
	ctx, req := t.decoder(r)
	resp, err := t.service.Encrypt(ctx, req)
	t.encoder(ctx, w, resp, err)
}

// Decrypt handles the decryption of ciphertext.
//
// @Summary Decrypt
// @Description Decrypts the provided ciphertext and returns the original plaintext.
// @Tags Cipher
// @Accept json
// @Produce json
// @Param Request body cipher.Request true "Ciphertext to decrypt"
// @Success 200 {object} cipher.Response "Decrypted text response"
// @Failure 400 {object} cipher.Response "Bad request"
// @Failure 500 {object} cipher.Response "Internal server error"
// @Router /api/cipher/decrypt [POST]
func (t *Transport) Decrypt(w http.ResponseWriter, r *http.Request) {
	ctx, req := t.decoder(r)
	resp, err := t.service.Decrypt(ctx, req)
	t.encoder(ctx, w, resp, err)
}

func (t *Transport) decoder(r *http.Request) (context.Context, cipher.Request) {
	ctx := context.WithValue(r.Context(), constants.ProcessID, uuid.New().String())
	ctx = context.WithValue(ctx, constants.IP, r.RemoteAddr)
	decoder := json.NewDecoder(r.Body)
	var req cipher.Request
	_ = decoder.Decode(&req)
	return ctx, req
}

func (t *Transport) encoder(ctx context.Context, w http.ResponseWriter, resp cipher.Response, err error) {
	w.Header().Set("Content-Type", "application/json")

	if v, ok := ctx.Value(constants.ProcessID).(string); ok {
		resp.ProcessID = v
	}

	var cfg config.IConfig
	if err != nil {
		path := getErrorPath(err)
		cfg = t.config.GetNestedConfig(fmt.Sprintf("response.errors.%s", path))
	} else {
		cfg = t.config.GetNestedConfig("response.success")
	}

	if cfg.GetInt("statusCode") == 0 && cfg.GetInt("status") == 0 {
		cfg = t.config.GetNestedConfig("response.errors.default")
	}

	resp.StatusCode = cfg.GetInt("statusCode")
	if resp.StatusCode == 0 {
		resp.StatusCode = 500
	}

	resp.Code = cfg.GetInt("code")
	resp.Message = cfg.GetString("message")

	w.WriteHeader(resp.StatusCode)
	_ = json.NewEncoder(w).Encode(resp)
}

func getErrorPath(err error) string {
	for s, path := range errorsCatalog.GetKeyByError {
		if errors.Is(err, s) {
			return path
		}
	}
	return "default"
}
