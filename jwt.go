package jwt

import (
	"errors"
	"unicode/utf8"

	jwtv3 "github.com/gbrlsnchs/jwt/v3"
)

type EncodeDecoder interface {
	Encode(interface{}) (string, error)
	Decode(string, interface{}) error
}

type encodeDecoder struct {
	alg *jwtv3.HMACSHA
}

var _ EncodeDecoder = &encodeDecoder{}

var ErrInvalidKey = errors.New("jwt: invalid HMAC secret key")

func NewEncodeDecoder(secretKey string) (EncodeDecoder, error) {
	if utf8.RuneCountInString(secretKey) < 32 {
		return nil, ErrInvalidKey
	}

	return &encodeDecoder{
		alg: jwtv3.NewHS256([]byte(secretKey)),
	}, nil
}

func (ed encodeDecoder) Encode(payload interface{}) (string, error) {
	token, err := jwtv3.Sign(payload, ed.alg)
	return string(token), err
}

func (ed encodeDecoder) Decode(token string, payload interface{}) error {
	_, err := jwtv3.Verify([]byte(token), ed.alg, payload)
	return err
}
