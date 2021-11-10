package jwt

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type CustomPayload struct {
	Payload
	Foo string `json:"foo,omitempty"`
	Bar string `json:"bar,omitempty"`
}

var testPayload = CustomPayload{
	Payload: Payload{
		Subject: "user42",
	},
	Foo: "Foo",
	Bar: "Bar",
}

func TestEncodeDecoder(t *testing.T) {
	tt := []struct {
		key           string
		payload       CustomPayload
		expectedError error
	}{
		{
			key:           "",
			payload:       testPayload,
			expectedError: ErrInvalidKey,
		},
		{
			key:           "",
			payload:       testPayload,
			expectedError: ErrInvalidKey,
		},
		{
			key:           "aaaaaaaaaabbbbbbbbbbcccc",
			payload:       testPayload,
			expectedError: ErrInvalidKey,
		},
		{
			key:           "12345678901234567890123456789012",
			payload:       testPayload,
			expectedError: nil,
		},
		{
			key:           "12345678901234567890123456789012",
			payload:       testPayload,
			expectedError: nil,
		},
		{
			key:           "12345678901234567890123456789012",
			payload:       testPayload,
			expectedError: nil,
		},
	}
	for _, tc := range tt {
		ed, err := New(tc.key)

		if tc.expectedError != nil {
			require.Equal(t, tc.expectedError, err)
			require.Nil(t, ed)
			continue
		}

		require.NoError(t, err)
		require.NotNil(t, ed)

		token, err := ed.Encode(tc.payload)
		require.NoError(t, err)
		require.NotEmpty(t, token)

		var validPayload CustomPayload

		err = ed.Decode(token, &validPayload)
		require.NoError(t, err)
		require.Equal(t, tc.payload, validPayload)

		var invalidPayload CustomPayload
		err = ed.Decode("INVALID TOKEN", &invalidPayload)
		require.Error(t, err)
		require.NotEqual(t, tc.payload, invalidPayload)
	}
}
