package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/SawitProRecruitment/UserService/repository"
	"github.com/SawitProRecruitment/UserService/utlis/jwtutils"
	"github.com/SawitProRecruitment/UserService/utlis/passwordutils"
	"github.com/SawitProRecruitment/UserService/utlis/validatorutlis"
	"github.com/google/uuid"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/SawitProRecruitment/UserService/generated"
	"github.com/labstack/echo/v4"
)

func (s *Server) getUserIdByAccessToken(ctx context.Context, tokenWithBearer string) (uuid.UUID, *generated.ErrorResponse) {
	var userID uuid.UUID

	jwtToken, err := jwtutils.ExtractToken(tokenWithBearer)
	if err != nil {
		return userID, &generated.ErrorResponse{
			Message: "Invalid or Unauthorized Access",
		}
	}

	accessToken, err := s.Repository.GetAccessTokenByToken(ctx, jwtToken)
	if err != nil {
		return userID, &generated.ErrorResponse{
			Message: "Invalid or Unauthorized Access",
		}
	}

	if accessToken.ExpirationAt.Before(time.Now()) {
		return userID, &generated.ErrorResponse{
			Message: "Access Token has expired",
		}
	}

	return accessToken.UserId, nil
}

func (s *Server) GetUser(ctx echo.Context, param generated.GetUserParams) error {
	userId, resErr := s.getUserIdByAccessToken(ctx.Request().Context(), param.Authorization)
	if resErr != nil {
		fmt.Println(resErr)
		return ctx.JSON(http.StatusForbidden, resErr)
	}

	user, err := s.Repository.GetUserByUserId(ctx.Request().Context(), userId)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, generated.ErrorResponse{
			Message: "Failed to retrieve user information",
		})
	}

	return ctx.JSON(http.StatusOK, generated.GetUserResponse{
		FullName:    user.FullName,
		PhoneNumber: user.PhoneNumber,
	})
}

func (s *Server) validateCreateUser(request generated.CreateUserJSONBody) *generated.ErrorResponse {
	var validationErrors []validatorutlis.ValidationError
	err := validatorutlis.IsValidUserFullName(request.FullName)
	if err != nil {
		validationErrors = append(validationErrors, validatorutlis.ValidationError{
			Column:  "fullName",
			Message: err.Error(),
		})
	}

	err = validatorutlis.IsValidIndonesiaPhoneNumber(request.PhoneNumber)
	if err != nil {
		validationErrors = append(validationErrors, validatorutlis.ValidationError{
			Column:  "phoneNumber",
			Message: err.Error(),
		})
	}

	err = validatorutlis.IsValidUserPassword(request.Password)
	if err != nil {
		validationErrors = append(validationErrors, validatorutlis.ValidationError{
			Column:  "password",
			Message: err.Error(),
		})
	}

	if len(validationErrors) > 0 {
		ve := make([]struct {
			Field   string `json:"field"`
			Message string `json:"message"`
		}, len(validationErrors))

		for i, val := range validationErrors {
			ve[i] = struct {
				Field   string `json:"field"`
				Message string `json:"message"`
			}{Field: val.Column, Message: val.Message}
		}

		return &generated.ErrorResponse{
			Message:          "Validation failed",
			ValidationErrors: &ve,
		}
	}

	return nil
}

func (s *Server) CreateUser(ctx echo.Context) error {
	body, err := io.ReadAll(ctx.Request().Body)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, generated.ErrorResponse{
			Message: validatorutlis.ErrReadRequestBody,
		})
	}

	var request generated.CreateUserJSONBody
	err = json.Unmarshal(body, &request)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, generated.ErrorResponse{
			Message: validatorutlis.ErrParseRequestBody,
		})
	}

	resErr := s.validateCreateUser(request)
	if resErr != nil {
		return ctx.JSON(http.StatusBadRequest, resErr)
	}

	passwordSalt, err := passwordutils.GeneratePasswordSalt()
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, generated.ErrorResponse{
			Message: "Error creating user: failed to generate password salt",
		})
	}

	passwordHash, err := passwordutils.HashPassword(request.Password, passwordSalt)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, generated.ErrorResponse{
			Message: "Error creating user: failed to hash password",
		})
	}

	err = s.Repository.CreateUser(ctx.Request().Context(), repository.CreateUserInput{
		FullName:     request.FullName,
		PhoneNumber:  request.PhoneNumber,
		PasswordHash: passwordHash,
		PasswordSalt: passwordSalt,
	})
	if errors.Is(err, repository.ErrDuplicateUserPhoneNumber) {
		return ctx.JSON(http.StatusConflict, generated.ErrorResponse{
			Message: "Error creating user: Phone Number is already registered",
		})
	}

	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, generated.ErrorResponse{
			Message: "Error creating user: database error",
		})
	}

	userId, err := s.Repository.GetUserIdByPhoneNumber(ctx.Request().Context(), request.PhoneNumber)
	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, generated.ErrorResponse{
			Message: "Error getting user ID: database error",
		})
	}

	return ctx.JSON(http.StatusCreated, generated.CreatedUserResponse{
		Id: userId.String(),
	})
}

func (s *Server) validateUpdateUser(request generated.UpdateUserJSONBody) *generated.ErrorResponse {
	hasFullName := request.FullName != nil
	hasPhoneNumber := request.PhoneNumber != nil
	if !hasFullName && !hasPhoneNumber {
		return &generated.ErrorResponse{
			Message: "at least one of the following must be provided: fullName, phoneNumber",
		}
	}

	var validationErrors []validatorutlis.ValidationError
	if hasFullName {
		err := validatorutlis.IsValidUserFullName(*request.FullName)
		if err != nil {
			validationErrors = append(validationErrors, validatorutlis.ValidationError{
				Column:  "fullName",
				Message: err.Error(),
			})
		}
	}

	if hasPhoneNumber {
		err := validatorutlis.IsValidIndonesiaPhoneNumber(*request.PhoneNumber)
		if err != nil {
			validationErrors = append(validationErrors, validatorutlis.ValidationError{
				Column:  "phoneNumber",
				Message: err.Error(),
			})
		}
	}

	if len(validationErrors) > 0 {
		ve := make([]struct {
			Field   string `json:"field"`
			Message string `json:"message"`
		}, len(validationErrors))

		for i, val := range validationErrors {
			ve[i] = struct {
				Field   string `json:"field"`
				Message string `json:"message"`
			}{Field: val.Column, Message: val.Message}
		}

		return &generated.ErrorResponse{
			Message:          "Validation failed",
			ValidationErrors: &ve,
		}
	}

	return nil
}

func (s *Server) UpdateUser(ctx echo.Context, param generated.UpdateUserParams) error {
	userId, resErr := s.getUserIdByAccessToken(ctx.Request().Context(), param.Authorization)
	if resErr != nil {
		return ctx.JSON(http.StatusForbidden, resErr)
	}

	body, err := io.ReadAll(ctx.Request().Body)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, generated.ErrorResponse{
			Message: validatorutlis.ErrReadRequestBody,
		})
	}

	var request generated.UpdateUserJSONBody
	err = json.Unmarshal(body, &request)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, generated.ErrorResponse{
			Message: validatorutlis.ErrParseRequestBody,
		})
	}

	errRes := s.validateUpdateUser(request)
	if errRes != nil {
		return ctx.JSON(http.StatusBadRequest, errRes)
	}

	err = s.Repository.UpdateUserByUserId(ctx.Request().Context(), repository.UpdateUserByUserIdInput{
		UserId:      userId,
		FullName:    request.FullName,
		PhoneNumber: request.PhoneNumber,
	})
	if errors.Is(err, repository.ErrDuplicateUserPhoneNumber) {
		return ctx.JSON(http.StatusConflict, generated.ErrorResponse{
			Message: "Error updating user: Phone Number is already registered",
		})
	}

	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, generated.ErrorResponse{
			Message: "Error updating user: database error",
		})
	}

	return ctx.JSON(http.StatusOK, nil)
}

func (s *Server) validateLoginUser(request generated.UserLoginJSONBody) *generated.ErrorResponse {
	var validationErrors []validatorutlis.ValidationError
	err := validatorutlis.IsValidIndonesiaPhoneNumber(request.PhoneNumber)
	if err != nil {
		validationErrors = append(validationErrors, validatorutlis.ValidationError{
			Column:  "phoneNumber",
			Message: err.Error(),
		})
	}

	err = validatorutlis.IsValidUserPassword(request.Password)
	if err != nil {
		validationErrors = append(validationErrors, validatorutlis.ValidationError{
			Column:  "password",
			Message: err.Error(),
		})
	}

	if len(validationErrors) > 0 {
		ve := make([]struct {
			Field   string `json:"field"`
			Message string `json:"message"`
		}, len(validationErrors))

		for i, val := range validationErrors {
			ve[i] = struct {
				Field   string `json:"field"`
				Message string `json:"message"`
			}{Field: val.Column, Message: val.Message}
		}

		return &generated.ErrorResponse{
			Message:          "Validation failed",
			ValidationErrors: &ve,
		}
	}

	return nil
}

func (s *Server) UserLogin(ctx echo.Context) error {
	body, err := io.ReadAll(ctx.Request().Body)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, generated.ErrorResponse{
			Message: validatorutlis.ErrReadRequestBody,
		})
	}

	var request generated.UserLoginJSONBody
	err = json.Unmarshal(body, &request)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, generated.ErrorResponse{
			Message: validatorutlis.ErrParseRequestBody,
		})
	}

	resErr := s.validateLoginUser(request)
	if resErr != nil {
		return ctx.JSON(http.StatusBadRequest, resErr)
	}

	user, err := s.Repository.GetUserWithPasswordByPhoneNumber(ctx.Request().Context(), request.PhoneNumber)
	if errors.Is(err, repository.ErrRowNotFound) {
		return ctx.JSON(http.StatusNotFound, generated.ErrorResponse{
			Message: "User not found",
		})
	}

	if err != nil {
		return ctx.JSON(http.StatusInternalServerError, generated.ErrorResponse{
			Message: "Error login: database error",
		})
	}

	err = passwordutils.ValidatePassword(passwordutils.GeneratePasswordWithSalt(request.Password, user.PasswordSalt), user.PasswordHash)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, generated.ErrorResponse{
			Message: "Incorrect password",
		})
	}

	oneHour := 1 * time.Hour
	generateJWTInput := jwtutils.GenerateJwtInput{
		SecretKey:        os.Getenv("JWT_SECRET_KEY"),
		UniqueIdentifier: user.Id.String(),
		ExpirationAt:     time.Now().Add(oneHour),
	}

	token, err := jwtutils.GenerateJWT(generateJWTInput)
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, generated.ErrorResponse{
			Message: "Error generating JWT",
		})
	}

	err = s.Repository.UserLogin(ctx.Request().Context(), repository.UserLoginInput{
		UserId:       user.Id,
		Token:        token,
		ExpirationAt: generateJWTInput.ExpirationAt,
	})
	if err != nil {
		return ctx.JSON(http.StatusBadRequest, generated.ErrorResponse{
			Message: "Error login: database error",
		})
	}

	return ctx.JSON(http.StatusOK, generated.UserLoginResponse{
		UserId:      user.Id.String(),
		AccessToken: "Bearer " + token,
	})
}
