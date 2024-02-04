package repository

import (
	"github.com/google/uuid"
	"time"
)

type GetUserWithPasswordByPhoneNumberOutput struct {
	Id           uuid.UUID
	PasswordHash string
	PasswordSalt string
}

type GetUserByUserIdOutput struct {
	FullName    string
	PhoneNumber string
}

type UpdateUserByUserIdInput struct {
	UserId      uuid.UUID
	FullName    *string
	PhoneNumber *string
}

type UserLoginInput struct {
	UserId       uuid.UUID
	Token        string
	ExpirationAt time.Time
}

type CreateUserInput struct {
	FullName     string
	PhoneNumber  string
	PasswordHash string
	PasswordSalt string
}

type GetAccessTokenByTokenOutput struct {
	UserId       uuid.UUID
	ExpirationAt time.Time
}
