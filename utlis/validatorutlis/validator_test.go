package validatorutlis

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_IsValidUserFullName(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		expectedErr error
	}{
		{
			name:        "when valid user full name",
			input:       "Hansen",
			expectedErr: nil,
		},
		{
			name:        "when invalid user full name on less than 3",
			input:       "Ha",
			expectedErr: errors.New("full name must be between 3 and 60 characters"),
		},
		{
			name:        "when invalid user full name on more than 60",
			input:       "John Doe with a Name that Exceeds Sixty Characters to Trigger Validation Error",
			expectedErr: errors.New("full name must be between 3 and 60 characters"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := IsValidUserFullName(tc.input)
			if tc.expectedErr == nil {
				assert.NoError(t, err)
				return
			}

			assert.Error(t, err)
			assert.EqualError(t, err, tc.expectedErr.Error())
		})
	}
}

func Test_IsValidIndonesiaPhoneNumber(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		expectedErr error
	}{
		{
			name:        "when valid indonesia phone number",
			input:       "+628111814032",
			expectedErr: nil,
		},
		{
			name:        "when invalid indonesia phone number on less than 10",
			input:       "+628111",
			expectedErr: errors.New("phone number must be between 10 and 13 characters and start with +62"),
		},
		{
			name:        "when invalid indonesia phone number on more than 13",
			input:       "+628111814032111812",
			expectedErr: errors.New("phone number must be between 10 and 13 characters and start with +62"),
		},
		{
			name:        "when invalid indonesia phone number on not start with +62",
			input:       "8111814032",
			expectedErr: errors.New("phone number must be between 10 and 13 characters and start with +62"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := IsValidIndonesiaPhoneNumber(tc.input)
			if tc.expectedErr == nil {
				assert.NoError(t, err)
				return
			}

			assert.Error(t, err)
			assert.EqualError(t, err, tc.expectedErr.Error())
		})
	}
}

func Test_IsValidUserPassword(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		expectedErr error
	}{
		{
			name:        "when valid user password",
			input:       "p4ssw@rD",
			expectedErr: nil,
		},
		{
			name:        "when invalid user password on less than 6",
			input:       "p4ssw",
			expectedErr: errors.New("password must be between 6 and 64 characters"),
		},
		{
			name:        "when invalid user password on more than 64",
			input:       "VeryLongPasswordThatExceedsSixtyFourCharactersAndWillTriggerValidationError123!@#",
			expectedErr: errors.New("password must be between 6 and 64 characters"),
		},
		{
			name:        "when invalid user password format no capital",
			input:       "p4ssw@rd",
			expectedErr: errors.New("password must have at least 1 capital, 1 number, and 1 special character"),
		},
		{
			name:        "when invalid user password format no number",
			input:       "passw@rD",
			expectedErr: errors.New("password must have at least 1 capital, 1 number, and 1 special character"),
		},
		{
			name:        "when invalid user password format no special character",
			input:       "p4ssworD",
			expectedErr: errors.New("password must have at least 1 capital, 1 number, and 1 special character"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := IsValidUserPassword(tc.input)
			if tc.expectedErr == nil {
				assert.NoError(t, err)
				return
			}

			assert.Error(t, err)
			assert.EqualError(t, err, tc.expectedErr.Error())
		})
	}
}
