package repository

import (
	"context"
	"github.com/google/uuid"
)

type RepositoryInterface interface {
	GetUserIdByPhoneNumber(ctx context.Context, phoneNumber string) (userId uuid.UUID, err error)
	CreateUser(ctx context.Context, input CreateUserInput) error
	GetUserWithPasswordByPhoneNumber(ctx context.Context, phoneNumber string) (output GetUserWithPasswordByPhoneNumberOutput, err error)
	GetUserByUserId(ctx context.Context, userId uuid.UUID) (output GetUserByUserIdOutput, err error)
	UpdateUserByUserId(ctx context.Context, input UpdateUserByUserIdInput) error

	GetAccessTokenByToken(ctx context.Context, accessToken string) (output GetAccessTokenByTokenOutput, err error)
	UserLogin(ctx context.Context, input UserLoginInput) error
}
