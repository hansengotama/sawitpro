package jwtutils

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func Test_GenerateJWT(t *testing.T) {
	testCases := []struct {
		name          string
		input         GenerateJwtInput
		expectedError bool
	}{
		{
			name: "Valid Input",
			input: GenerateJwtInput{
				SecretKey:        "your-secret-key",
				UniqueIdentifier: "user123",
				ExpirationAt:     time.Now().Add(time.Hour),
			},
			expectedError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token, err := GenerateJWT(tc.input)
			if tc.expectedError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotEmpty(t, token)
		})
	}
}

func TestExtractToken(t *testing.T) {
	testCases := []struct {
		name          string
		input         string
		expectedToken string
		expectedError bool
	}{
		{
			name:          "Valid Token",
			input:         "Bearer abcdefg123456",
			expectedToken: "abcdefg123456",
			expectedError: false,
		},
		{
			name:          "Invalid Token Format",
			input:         "InvalidFormat",
			expectedToken: "",
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token, err := ExtractToken(tc.input)
			if tc.expectedError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedToken, token)
		})
	}
}
