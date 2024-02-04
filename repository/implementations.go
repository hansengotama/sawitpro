package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"time"
)

var maximumQueryTime = 5 * time.Second

func (r *Repository) GetUserIdByPhoneNumber(ctx context.Context, phoneNumber string) (uuid.UUID, error) {
	ctx, cancel := context.WithTimeout(ctx, maximumQueryTime)
	defer cancel()

	var userId uuid.UUID
	row := r.Db.QueryRowContext(ctx, "SELECT id FROM users WHERE phone_number = $1", phoneNumber)
	if row.Err() != nil {
		return userId, row.Err()
	}

	err := row.Scan(&userId)
	isNotFound := errors.Is(err, sql.ErrNoRows)
	if isNotFound {
		return userId, ErrRowNotFound
	}

	if err != nil {
		// Logging
		return userId, err
	}

	return userId, err
}

func (r *Repository) GetUserWithPasswordByPhoneNumber(ctx context.Context, phoneNumber string) (GetUserWithPasswordByPhoneNumberOutput, error) {
	ctx, cancel := context.WithTimeout(ctx, maximumQueryTime)
	defer cancel()

	var output GetUserWithPasswordByPhoneNumberOutput
	row := r.Db.QueryRowContext(ctx, "SELECT id, password_hash, password_salt FROM users WHERE phone_number = $1", phoneNumber)
	if row.Err() != nil {
		return output, row.Err()
	}

	err := row.Scan(&output.Id, &output.PasswordHash, &output.PasswordSalt)
	isNotFound := errors.Is(err, sql.ErrNoRows)
	if isNotFound {
		return output, ErrRowNotFound
	}

	if err != nil {
		// Logging
		return output, err
	}

	return output, err
}

func (r *Repository) GetUserByUserId(ctx context.Context, userId uuid.UUID) (GetUserByUserIdOutput, error) {
	ctx, cancel := context.WithTimeout(ctx, maximumQueryTime)
	defer cancel()

	var output GetUserByUserIdOutput
	row := r.Db.QueryRowContext(ctx, "SELECT full_name, phone_number FROM users WHERE id = $1", userId)
	if row.Err() != nil {
		return output, row.Err()
	}

	err := row.Scan(&output.FullName, &output.PhoneNumber)
	isNotFound := errors.Is(err, sql.ErrNoRows)
	if isNotFound {
		return output, ErrRowNotFound
	}

	if err != nil {
		// Logging
		return output, err
	}

	return output, err
}

func (r *Repository) GetAccessTokenByToken(ctx context.Context, accessToken string) (GetAccessTokenByTokenOutput, error) {
	ctx, cancel := context.WithTimeout(ctx, maximumQueryTime)
	defer cancel()

	var output GetAccessTokenByTokenOutput
	row := r.Db.QueryRowContext(ctx, "SELECT user_id, expiration_at FROM access_tokens WHERE token = $1", accessToken)
	if row.Err() != nil {
		return output, row.Err()
	}

	err := row.Scan(&output.UserId, &output.ExpirationAt)
	isNotFound := errors.Is(err, sql.ErrNoRows)
	if isNotFound {
		return output, ErrRowNotFound
	}

	if err != nil {
		// Logging
		return output, err
	}

	return output, nil
}

func (r *Repository) UpdateUserByUserId(ctx context.Context, input UpdateUserByUserIdInput) error {
	ctx, cancel := context.WithTimeout(ctx, maximumQueryTime)
	defer cancel()

	query := "UPDATE users "
	additionalQuery := "SET "

	var updates []any
	if input.FullName != nil {
		updates = append(updates, input.FullName)
		query += additionalQuery + fmt.Sprintf("full_name = $%d", len(updates))
		additionalQuery = ", "
	}

	if input.PhoneNumber != nil {
		updates = append(updates, input.PhoneNumber)
		query += additionalQuery + fmt.Sprintf("phone_number = $%d", len(updates))
		additionalQuery = ", "
	}

	isHasUpdate := len(updates) > 0
	if !isHasUpdate {
		// Logging
		return ErrNoUpdateNeeded
	}

	updates = append(updates, time.Now())
	query += additionalQuery + fmt.Sprintf("updated_at = $%d", len(updates))

	updates = append(updates, input.UserId)
	query += fmt.Sprintf(" WHERE id = $%d", len(updates))

	_, err := r.Db.ExecContext(ctx, query, updates...)
	if err != nil && err.Error() == ErrDuplicateUserPhoneNumber.Error() {
		return ErrDuplicateUserPhoneNumber
	}

	if err != nil {
		// Logging
		return err
	}

	return nil
}

func (r *Repository) UserLogin(ctx context.Context, input UserLoginInput) error {
	ctx, cancel := context.WithTimeout(ctx, maximumQueryTime)
	defer cancel()

	tx, err := r.Db.Begin()
	if err != nil {
		// Logging
		return err
	}

	defer func() {
		if err != nil {
			err := tx.Rollback()
			if err != nil {
				// Logging
				return
			}
		}
	}()

	query := "INSERT INTO access_tokens(user_id, token, expiration_at) VALUES ($1, $2, $3)"
	values := []any{input.UserId, input.Token, input.ExpirationAt}
	_, err = tx.ExecContext(ctx, query, values...)
	if err != nil {
		// Logging
		return err
	}

	// Developer's opinion: Instead of manual counting, we can query the 'access_tokens' table
	// to retrieve the count of created access tokens or leverage a virtual table.
	query = "UPDATE users SET successful_login = successful_login + 1 WHERE id = $1"
	_, err = tx.ExecContext(ctx, query, input.UserId)
	if err != nil {
		// Logging
		return err
	}

	err = tx.Commit()
	if err != nil {
		// Logging
		return err
	}

	return nil
}

func (r *Repository) CreateUser(ctx context.Context, input CreateUserInput) error {
	ctx, cancel := context.WithTimeout(ctx, maximumQueryTime)
	defer cancel()

	query := "INSERT INTO users(full_name, phone_number, password_hash, password_salt) VALUES ($1, $2, $3, $4)"
	values := []any{input.FullName, input.PhoneNumber, input.PasswordHash, input.PasswordSalt}
	_, err := r.Db.ExecContext(ctx, query, values...)
	if err != nil && err.Error() == ErrDuplicateUserPhoneNumber.Error() {
		return ErrDuplicateUserPhoneNumber
	}

	if err != nil {
		// Logging
		return err
	}

	return nil
}
