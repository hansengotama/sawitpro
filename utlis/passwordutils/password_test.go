package passwordutils

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_GeneratePasswordSalt(t *testing.T) {
	const iterations = 100

	salts := make(map[string]struct{})

	for i := 0; i < iterations; i++ {
		salt, err := GeneratePasswordSalt()

		assert.NoError(t, err)
		assert.Len(t, salt, 64)
		_, exists := salts[salt]
		assert.False(t, exists)

		salts[salt] = struct{}{}
	}
}

func Test_GenerateAndValidatePassword(t *testing.T) {
	testCases := []struct {
		name     string
		password string
		salt     string
	}{
		{
			name:     "Valid Password (1)",
			password: "password123",
			salt:     "randomsalt",
		},
		{
			name:     "Valid Password (2)",
			password: "weakpassword",
			salt:     "anothersalt",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate password hash
			hashedPassword, err := HashPassword(tc.password, tc.salt)
			assert.NoError(t, err)
			assert.NotEmpty(t, hashedPassword)

			// Validate password
			err = ValidatePassword(GeneratePasswordWithSalt(tc.password, tc.salt), hashedPassword)
			assert.NoError(t, err)
		})
	}
}
