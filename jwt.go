package jwt

import (
	"errors"
	"unicode/utf8"

	jwtv3 "github.com/gbrlsnchs/jwt/v3"
)

type EncodeDecoder struct {
	alg *jwtv3.HMACSHA
}

var ErrInvalidKey = errors.New("jwt: invalid HMAC secret key")

func New(secretKey string) (*EncodeDecoder, error) {
	if utf8.RuneCountInString(secretKey) < 32 {
		return nil, ErrInvalidKey
	}

	return &EncodeDecoder{
		alg: jwtv3.NewHS256([]byte(secretKey)),
	}, nil
}

func (ed EncodeDecoder) Encode(payload interface{}) (string, error) {
	token, err := jwtv3.Sign(payload, ed.alg)
	return string(token), err
}

func (ed EncodeDecoder) Decode(token string, payload interface{}) error {
	_, err := jwtv3.Verify([]byte(token), ed.alg, payload)
	return err
}
