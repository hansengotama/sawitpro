package passwordutils

import (
	"crypto/rand"
	"encoding/hex"
	"golang.org/x/crypto/bcrypt"
)

func GeneratePasswordSalt() (string, error) {
	saltBytes := make([]byte, 32)
	_, err := rand.Read(saltBytes)
	if err != nil {
		return "", err
	}

	salt := hex.EncodeToString(saltBytes)

	return salt, nil
}

func HashPassword(password, salt string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(GeneratePasswordWithSalt(password, salt)), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hashedPassword), nil
}

func ValidatePassword(plainPassword, hashedPassword string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(plainPassword))
}

func GeneratePasswordWithSalt(password, salt string) string {
	return password + salt
}
