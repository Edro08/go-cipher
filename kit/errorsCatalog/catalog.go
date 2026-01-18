package errorsCatalog

import "errors"

// ------------------------------------------------------------------------------------------
// ERROR MAP
// ------------------------------------------------------------------------------------------

var GetKeyByError = map[error]string{
	ErrNotImplemented:        "notImplemented",
	ErrDecryptFailed:         "decryptFailed",
	ErrEncryptFailed:         "encryptFailed",
	ErrDecodeBase64:          "decodeBase64",
	ErrPrivateKeyNotFound:    "privateKeyNotFound",
	ErrPublicKeyNotFound:     "publicKeyNotFound",
	ErrDecodePEMBlockPrivate: "decodePEMBlockPrivate",
	ErrDecodePEMBlockPublic:  "decodePEMBlockPublic",
	ErrParsePrivateKey:       "parsePrivateKey",
	ErrParsePublicKey:        "parsePublicKey",
	ErrCreateCipherBlock:     "createCipherBlock",
	ErrCreateGCM:             "createGCM",
	ErrGenerateNonce:         "generateNonce",
}

// ------------------------------------------------------------------------------------------
// COMMON
// ------------------------------------------------------------------------------------------

var (
	ErrNotImplemented = errors.New("not implemented")
	ErrDecryptFailed  = errors.New("decrypt failed")
	ErrEncryptFailed  = errors.New("encrypt failed")
	ErrDecodeBase64   = errors.New("failed to decode base64")
)

// ------------------------------------------------------------------------------------------
// RSA
// ------------------------------------------------------------------------------------------
var (
	ErrPrivateKeyNotFound    = errors.New("private key not found")
	ErrPublicKeyNotFound     = errors.New("public key not found")
	ErrDecodePEMBlockPrivate = errors.New("failed to decode PEM block containing private key")
	ErrDecodePEMBlockPublic  = errors.New("failed to decode PEM block containing public key")
	ErrParsePrivateKey       = errors.New("failed to parse private key")
	ErrParsePublicKey        = errors.New("failed to parse public key")
)

// ------------------------------------------------------------------------------------------
// AES
// ------------------------------------------------------------------------------------------
var (
	ErrCreateCipherBlock = errors.New("failed to create cipher block")
	ErrCreateGCM         = errors.New("failed to create GCM")
	ErrGenerateNonce     = errors.New("failed to generate nonce")
)
