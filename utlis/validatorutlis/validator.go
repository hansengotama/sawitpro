package validatorutlis

import (
	"errors"
	"strings"
	"unicode"
)

const (
	ErrReadRequestBody  = "Error read request body"
	ErrParseRequestBody = "Error parsing request body"
)

type ValidationError struct {
	Column  string
	Message string
}

func IsValidUserFullName(fullName string) error {
	if len(fullName) < 3 || len(fullName) > 60 {
		return errors.New("full name must be between 3 and 60 characters")
	}

	return nil
}

func IsValidIndonesiaPhoneNumber(phoneNumber string) error {
	if len(phoneNumber) < 10 || len(phoneNumber) > 13 || !strings.HasPrefix(phoneNumber, "+62") {
		return errors.New("phone number must be between 10 and 13 characters and start with +62")
	}

	return nil
}

func IsValidUserPassword(password string) error {
	if len(password) < 6 || len(password) > 64 {
		return errors.New("password must be between 6 and 64 characters")
	}

	hasCapital := false
	hasNumber := false
	hasSpecialChar := false

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasCapital = true
		case unicode.IsDigit(char):
			hasNumber = true
		case !unicode.IsLetter(char) && !unicode.IsDigit(char):
			hasSpecialChar = true
		}
	}

	if hasCapital && hasNumber && hasSpecialChar {
		return nil
	}

	return errors.New("password must have at least 1 capital, 1 number, and 1 special character")
}
