package cipher

import "context"

type IService interface {
	Encrypt(ctx context.Context, req Request) (Response, error)
	Decrypt(ctx context.Context, req Request) (Response, error)
}

type Request struct {
	Profile string `json:"profile" example:"default"`
	Value   string `json:"value" example:"hello world"`
}

type Response struct {
	ProcessID  string `json:"processID" example:"123456789"`
	StatusCode int    `json:"-" example:"400"`
	Code       int    `json:"code" example:"400"`
	Message    string `json:"message" example:"Bad Request"`
	Profile    string `json:"profile,omitempty" example:"default"`
	Value      string `json:"value,omitempty" example:"hello world"`
}
