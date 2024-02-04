package handler

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/hansengotama/sawitpro/generated"
	"github.com/hansengotama/sawitpro/repository"
	"github.com/hansengotama/sawitpro/utlis/jwtutils"
	"github.com/hansengotama/sawitpro/utlis/passwordutils"
	"github.com/hansengotama/sawitpro/utlis/validatorutlis"
	"github.com/labstack/echo/v4"
	"github.com/procodr/monkey"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func Test_GetUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := repository.NewMockRepositoryInterface(ctrl)
	s := NewServer(NewServerOptions{
		Repository: mockRepo,
	})

	userId := uuid.New()

	testCases := []struct {
		name                string
		before              func()
		authorizationHeader string
		expectedStatusCode  int
		expectedResponse    any
	}{
		{
			name: "when successfully get user",
			before: func() {
				mockRepo.
					EXPECT().
					GetAccessTokenByToken(context.Background(), "valid_token").
					Return(repository.GetAccessTokenByTokenOutput{
						UserId:       userId,
						ExpirationAt: time.Now().Add(1 * time.Hour),
					}, nil).
					Times(1)

				mockRepo.
					EXPECT().
					GetUserByUserId(context.Background(), userId).
					Return(repository.GetUserByUserIdOutput{
						FullName:    "Hansen",
						PhoneNumber: "+628111814032",
					}, nil).
					Times(1)
			},
			authorizationHeader: "Bearer valid_token",
			expectedStatusCode:  http.StatusOK,
			expectedResponse: generated.GetUserResponse{
				FullName:    "Hansen",
				PhoneNumber: "+628111814032",
			},
		},
		{
			name:                "when failed get user on invalid authorization header",
			before:              nil,
			authorizationHeader: "invalid",
			expectedStatusCode:  http.StatusForbidden,
			expectedResponse: generated.ErrorResponse{
				Message: "Invalid or Unauthorized Access",
			},
		},
		{
			name: "when failed get user on GetAccessTokenByToken repo function",
			before: func() {
				mockRepo.
					EXPECT().
					GetAccessTokenByToken(context.Background(), "valid_token").
					Return(repository.GetAccessTokenByTokenOutput{}, errors.New("error on GetAccessTokenByToken")).
					Times(1)
			},
			authorizationHeader: "Bearer valid_token",
			expectedStatusCode:  http.StatusForbidden,
			expectedResponse: generated.ErrorResponse{
				Message: "Invalid or Unauthorized Access",
			},
		},
		{
			name: "when failed get user on token already expired",
			before: func() {
				mockRepo.
					EXPECT().
					GetAccessTokenByToken(context.Background(), "valid_token").
					Return(repository.GetAccessTokenByTokenOutput{
						UserId:       userId,
						ExpirationAt: time.Now().Add(-1 * time.Hour),
					}, nil).
					Times(1)
			},
			authorizationHeader: "Bearer valid_token",
			expectedStatusCode:  http.StatusForbidden,
			expectedResponse: generated.ErrorResponse{
				Message: "Access Token has expired",
			},
		},
		{
			name: "when failed get user on GetUserByUserId repo function",
			before: func() {
				mockRepo.
					EXPECT().
					GetAccessTokenByToken(context.Background(), "valid_token").
					Return(repository.GetAccessTokenByTokenOutput{
						UserId:       userId,
						ExpirationAt: time.Now().Add(1 * time.Hour),
					}, nil).
					Times(1)

				mockRepo.EXPECT().GetUserByUserId(context.Background(), userId).Return(repository.GetUserByUserIdOutput{}, errors.New("error on GetUserByUserId")).Times(1)
			},
			authorizationHeader: "Bearer valid_token",
			expectedStatusCode:  http.StatusInternalServerError,
			expectedResponse: generated.ErrorResponse{
				Message: "Failed to retrieve user information",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.before != nil {
				tc.before()
			}

			e := echo.New()
			req := httptest.NewRequest(http.MethodGet, "/users", nil)
			rec := httptest.NewRecorder()

			c := e.NewContext(req, rec)
			c.Request().Header.Set("Authorization", tc.authorizationHeader)

			err := s.GetUser(c, generated.GetUserParams{Authorization: tc.authorizationHeader})
			assert.NoError(t, err)

			assert.Equal(t, tc.expectedStatusCode, rec.Code)

			switch eRes := tc.expectedResponse.(type) {
			case generated.GetUserResponse:
				var response generated.GetUserResponse
				err = json.Unmarshal(rec.Body.Bytes(), &response)
				assert.Equal(t, eRes, response)
				return
			case generated.ErrorResponse:
				var response generated.ErrorResponse
				err = json.Unmarshal(rec.Body.Bytes(), &response)
				assert.Equal(t, eRes, response)
			}
		})
	}
}

type errorReaderCloser struct{}

func (e *errorReaderCloser) Read(p []byte) (n int, err error) {
	return 0, errors.New("simulated read error")
}

func (e *errorReaderCloser) Close() error {
	return nil
}

func Test_UpdateUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := repository.NewMockRepositoryInterface(ctrl)
	s := NewServer(NewServerOptions{
		Repository: mockRepo,
	})

	userId := uuid.New()
	fullName := "Hansen"
	phoneNumber := "+628111814032"

	testCases := []struct {
		name                string
		before              func()
		httpReq             *http.Request
		authorizationHeader string
		expectedStatusCode  int
		expectedResponse    any
	}{
		{
			name: "when successfully update user full name and phone number",
			before: func() {
				mockRepo.
					EXPECT().
					GetAccessTokenByToken(context.Background(), "valid_token").
					Return(repository.GetAccessTokenByTokenOutput{
						UserId:       userId,
						ExpirationAt: time.Now().Add(1 * time.Hour),
					}, nil).
					Times(1)

				mockRepo.
					EXPECT().
					UpdateUserByUserId(context.Background(), repository.UpdateUserByUserIdInput{
						UserId:      userId,
						FullName:    &fullName,
						PhoneNumber: &phoneNumber,
					}).
					Return(nil).
					Times(1)
			},
			httpReq:             httptest.NewRequest(http.MethodPatch, "/users", strings.NewReader(`{"fullName": "Hansen", "phoneNumber": "+628111814032"}`)),
			authorizationHeader: "Bearer valid_token",
			expectedStatusCode:  http.StatusOK,
			expectedResponse:    nil,
		},
		{
			name: "when successfully update user full name",
			before: func() {
				mockRepo.
					EXPECT().
					GetAccessTokenByToken(context.Background(), "valid_token").
					Return(repository.GetAccessTokenByTokenOutput{
						UserId:       userId,
						ExpirationAt: time.Now().Add(1 * time.Hour),
					}, nil).
					Times(1)

				mockRepo.
					EXPECT().
					UpdateUserByUserId(context.Background(), repository.UpdateUserByUserIdInput{
						UserId:   userId,
						FullName: &fullName,
					}).
					Return(nil).
					Times(1)
			},
			httpReq:             httptest.NewRequest(http.MethodPatch, "/users", strings.NewReader(`{"fullName": "Hansen"}`)),
			authorizationHeader: "Bearer valid_token",
			expectedStatusCode:  http.StatusOK,
			expectedResponse:    nil,
		},
		{
			name: "when successfully update user phone number",
			before: func() {
				mockRepo.
					EXPECT().
					GetAccessTokenByToken(context.Background(), "valid_token").
					Return(repository.GetAccessTokenByTokenOutput{
						UserId:       userId,
						ExpirationAt: time.Now().Add(1 * time.Hour),
					}, nil).
					Times(1)

				mockRepo.
					EXPECT().
					UpdateUserByUserId(context.Background(), repository.UpdateUserByUserIdInput{
						UserId:      userId,
						PhoneNumber: &phoneNumber,
					}).
					Return(nil).
					Times(1)
			},
			httpReq:             httptest.NewRequest(http.MethodPatch, "/users", strings.NewReader(`{"phoneNumber": "+628111814032"}`)),
			authorizationHeader: "Bearer valid_token",
			expectedStatusCode:  http.StatusOK,
			expectedResponse:    nil,
		},
		{
			name:                "when failed get user on invalid authorization header",
			before:              nil,
			httpReq:             httptest.NewRequest(http.MethodPatch, "/users", nil),
			authorizationHeader: "invalid",
			expectedStatusCode:  http.StatusForbidden,
			expectedResponse: generated.ErrorResponse{
				Message: "Invalid or Unauthorized Access",
			},
		},
		{
			name: "when failed update user on GetAccessTokenByToken repo function",
			before: func() {
				mockRepo.
					EXPECT().
					GetAccessTokenByToken(context.Background(), "valid_token").
					Return(repository.GetAccessTokenByTokenOutput{}, errors.New("error on GetAccessTokenByToken")).
					Times(1)
			},
			httpReq:             httptest.NewRequest(http.MethodPatch, "/users", nil),
			authorizationHeader: "Bearer valid_token",
			expectedStatusCode:  http.StatusForbidden,
			expectedResponse: generated.ErrorResponse{
				Message: "Invalid or Unauthorized Access",
			},
		},
		{
			name: "when failed update user on token already expired",
			before: func() {
				mockRepo.
					EXPECT().
					GetAccessTokenByToken(context.Background(), "valid_token").
					Return(repository.GetAccessTokenByTokenOutput{
						UserId:       userId,
						ExpirationAt: time.Now().Add(-1 * time.Hour),
					}, nil).
					Times(1)
			},
			httpReq:             httptest.NewRequest(http.MethodPatch, "/users", nil),
			authorizationHeader: "Bearer valid_token",
			expectedStatusCode:  http.StatusForbidden,
			expectedResponse: generated.ErrorResponse{
				Message: "Access Token has expired",
			},
		},
		{
			name: "when failed update user on read request body",
			before: func() {
				mockRepo.
					EXPECT().
					GetAccessTokenByToken(context.Background(), "valid_token").
					Return(repository.GetAccessTokenByTokenOutput{
						UserId:       userId,
						ExpirationAt: time.Now().Add(1 * time.Hour),
					}, nil).
					Times(1)
			},
			httpReq:             httptest.NewRequest(http.MethodPatch, "/users", &errorReaderCloser{}),
			authorizationHeader: "Bearer valid_token",
			expectedStatusCode:  http.StatusBadRequest,
			expectedResponse: generated.ErrorResponse{
				Message: validatorutlis.ErrReadRequestBody,
			},
		},
		{
			name: "when failed update user on parse request body",
			before: func() {
				mockRepo.
					EXPECT().
					GetAccessTokenByToken(context.Background(), "valid_token").
					Return(repository.GetAccessTokenByTokenOutput{
						UserId:       userId,
						ExpirationAt: time.Now().Add(1 * time.Hour),
					}, nil).
					Times(1)
			},
			httpReq:             httptest.NewRequest(http.MethodPatch, "/users", nil),
			authorizationHeader: "Bearer valid_token",
			expectedStatusCode:  http.StatusBadRequest,
			expectedResponse: generated.ErrorResponse{
				Message: validatorutlis.ErrParseRequestBody,
			},
		},
		{
			name: "when failed update user on empty request body",
			before: func() {
				mockRepo.
					EXPECT().
					GetAccessTokenByToken(context.Background(), "valid_token").
					Return(repository.GetAccessTokenByTokenOutput{
						UserId:       userId,
						ExpirationAt: time.Now().Add(1 * time.Hour),
					}, nil).
					Times(1)
			},
			httpReq:             httptest.NewRequest(http.MethodPatch, "/users", strings.NewReader(`{}`)),
			authorizationHeader: "Bearer valid_token",
			expectedStatusCode:  http.StatusBadRequest,
			expectedResponse: generated.ErrorResponse{
				Message: "at least one of the following must be provided: fullName, phoneNumber",
			},
		},
		{
			name: "when failed update user on error validate fullName",
			before: func() {
				mockRepo.
					EXPECT().
					GetAccessTokenByToken(context.Background(), "valid_token").
					Return(repository.GetAccessTokenByTokenOutput{
						UserId:       userId,
						ExpirationAt: time.Now().Add(1 * time.Hour),
					}, nil).
					Times(1)
			},
			httpReq:             httptest.NewRequest(http.MethodPatch, "/users", strings.NewReader(`{"fullName": "aa"}`)),
			authorizationHeader: "Bearer valid_token",
			expectedStatusCode:  http.StatusBadRequest,
			expectedResponse: generated.ErrorResponse{
				Message: "Validation failed",
				ValidationErrors: &[]struct {
					Field   string `json:"field"`
					Message string `json:"message"`
				}{
					{
						Field:   "fullName",
						Message: "full name must be between 3 and 60 characters",
					},
				},
			},
		},
		{
			name: "when failed update user on error validate phoneNumber",
			before: func() {
				mockRepo.
					EXPECT().
					GetAccessTokenByToken(context.Background(), "valid_token").
					Return(repository.GetAccessTokenByTokenOutput{
						UserId:       userId,
						ExpirationAt: time.Now().Add(1 * time.Hour),
					}, nil).
					Times(1)
			},
			httpReq:             httptest.NewRequest(http.MethodPatch, "/users", strings.NewReader(`{"phoneNumber": "8111814032"}`)),
			authorizationHeader: "Bearer valid_token",
			expectedStatusCode:  http.StatusBadRequest,
			expectedResponse: generated.ErrorResponse{
				Message: "Validation failed",
				ValidationErrors: &[]struct {
					Field   string `json:"field"`
					Message string `json:"message"`
				}{
					{
						Field:   "phoneNumber",
						Message: "phone number must be between 10 and 13 characters and start with +62",
					},
				},
			},
		},
		{
			name: "when failed update user on error conflict phone number UpdateUserByUserId repo function",
			before: func() {
				mockRepo.
					EXPECT().
					GetAccessTokenByToken(context.Background(), "valid_token").
					Return(repository.GetAccessTokenByTokenOutput{
						UserId:       userId,
						ExpirationAt: time.Now().Add(1 * time.Hour),
					}, nil).
					Times(1)

				mockRepo.
					EXPECT().
					UpdateUserByUserId(context.Background(), repository.UpdateUserByUserIdInput{
						UserId:   userId,
						FullName: &fullName,
					}).
					Return(repository.ErrDuplicateUserPhoneNumber).
					Times(1)
			},
			httpReq:             httptest.NewRequest(http.MethodPatch, "/users", strings.NewReader(`{"fullName": "Hansen"}`)),
			authorizationHeader: "Bearer valid_token",
			expectedStatusCode:  http.StatusConflict,
			expectedResponse: generated.ErrorResponse{
				Message: "Error updating user: Phone Number is already registered",
			},
		},
		{
			name: "when failed update user on error UpdateUserByUserId repo function",
			before: func() {
				mockRepo.
					EXPECT().
					GetAccessTokenByToken(context.Background(), "valid_token").
					Return(repository.GetAccessTokenByTokenOutput{
						UserId:       userId,
						ExpirationAt: time.Now().Add(1 * time.Hour),
					}, nil).
					Times(1)

				mockRepo.
					EXPECT().
					UpdateUserByUserId(context.Background(), repository.UpdateUserByUserIdInput{
						UserId:   userId,
						FullName: &fullName,
					}).
					Return(errors.New("error UpdateUserByUserId repo")).
					Times(1)
			},
			httpReq:             httptest.NewRequest(http.MethodPatch, "/users", strings.NewReader(`{"fullName": "Hansen"}`)),
			authorizationHeader: "Bearer valid_token",
			expectedStatusCode:  http.StatusInternalServerError,
			expectedResponse: generated.ErrorResponse{
				Message: "Error updating user: database error",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.before != nil {
				tc.before()
			}

			e := echo.New()
			req := tc.httpReq
			rec := httptest.NewRecorder()

			c := e.NewContext(req, rec)
			c.Request().Header.Set("Authorization", tc.authorizationHeader)

			err := s.UpdateUser(c, generated.UpdateUserParams{Authorization: tc.authorizationHeader})
			assert.NoError(t, err)

			assert.Equal(t, tc.expectedStatusCode, rec.Code)

			switch eRes := tc.expectedResponse.(type) {
			case nil:
				assert.Nil(t, eRes)
			case generated.ErrorResponse:
				var response generated.ErrorResponse
				err = json.Unmarshal(rec.Body.Bytes(), &response)
				assert.Equal(t, eRes, response)
			}
		})
	}
}

func Test_CreateUser(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := repository.NewMockRepositoryInterface(ctrl)
	s := NewServer(NewServerOptions{
		Repository: mockRepo,
	})

	userId := uuid.New()

	testCases := []struct {
		name               string
		before             func()
		httpReq            *http.Request
		expectedStatusCode int
		expectedResponse   any
	}{
		{
			name: "when successfully create user",
			before: func() {
				monkey.Patch(passwordutils.GeneratePasswordSalt, func() (string, error) {
					return "password_salt", nil
				})

				monkey.Patch(passwordutils.HashPassword, func(password, salt string) (string, error) {
					return "password_hash", nil
				})

				mockRepo.
					EXPECT().
					CreateUser(
						context.Background(),
						repository.CreateUserInput{
							FullName:     "Hansen",
							PhoneNumber:  "+628111814032",
							PasswordHash: "password_hash",
							PasswordSalt: "password_salt",
						},
					).
					Return(nil)

				mockRepo.
					EXPECT().
					GetUserIdByPhoneNumber(
						context.Background(),
						"+628111814032",
					).
					Return(userId, nil).
					Times(1)
			},
			httpReq:            httptest.NewRequest(http.MethodPost, "/users", strings.NewReader(`{"fullName": "Hansen", "phoneNumber": "+628111814032", "password": "p4ssw@rD"}`)),
			expectedStatusCode: http.StatusCreated,
			expectedResponse: generated.CreatedUserResponse{
				Id: userId.String(),
			},
		},
		{
			name:               "when failed create user on read request body",
			before:             nil,
			httpReq:            httptest.NewRequest(http.MethodPost, "/users", &errorReaderCloser{}),
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse: generated.ErrorResponse{
				Message: validatorutlis.ErrReadRequestBody,
			},
		},
		{
			name:               "when failed create user on parse request body",
			before:             nil,
			httpReq:            httptest.NewRequest(http.MethodPost, "/users", nil),
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse: generated.ErrorResponse{
				Message: validatorutlis.ErrParseRequestBody,
			},
		},
		{
			name:               "when failed create user on validation failed",
			before:             nil,
			httpReq:            httptest.NewRequest(http.MethodPost, "/users", strings.NewReader(`{"fullName": "", "phoneNumber": "", "password": ""}`)),
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse: generated.ErrorResponse{
				Message: "Validation failed",
				ValidationErrors: &[]struct {
					Field   string `json:"field"`
					Message string `json:"message"`
				}{
					{
						Field:   "fullName",
						Message: "full name must be between 3 and 60 characters",
					},
					{
						Field:   "phoneNumber",
						Message: "phone number must be between 10 and 13 characters and start with +62",
					},
					{
						Field:   "password",
						Message: "password must be between 6 and 64 characters",
					},
				},
			},
		},
		{
			name:               "when failed create user on invalid password format",
			before:             nil,
			httpReq:            httptest.NewRequest(http.MethodPost, "/users", strings.NewReader(`{"fullName": "Hansen", "phoneNumber": "+628111814032", "password": "password"}`)),
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse: generated.ErrorResponse{
				Message: "Validation failed",
				ValidationErrors: &[]struct {
					Field   string `json:"field"`
					Message string `json:"message"`
				}{
					{
						Field:   "password",
						Message: "password must have at least 1 capital, 1 number, and 1 special character",
					},
				},
			},
		},
		{
			name: "when failed create user on error GeneratePasswordSalt",
			before: func() {
				monkey.Patch(passwordutils.GeneratePasswordSalt, func() (string, error) {
					return "", errors.New("error on GeneratePasswordSalt")
				})

				monkey.Patch(passwordutils.HashPassword, func(password, salt string) (string, error) {
					return "password_hash", nil
				})
			},
			httpReq:            httptest.NewRequest(http.MethodPost, "/users", strings.NewReader(`{"fullName": "Hansen", "phoneNumber": "+628111814032", "password": "p4ssw@rD"}`)),
			expectedStatusCode: http.StatusInternalServerError,
			expectedResponse: generated.ErrorResponse{
				Message: "Error creating user: failed to generate password salt",
			},
		},
		{
			name: "when failed create user on error HashPassword",
			before: func() {
				monkey.Patch(passwordutils.GeneratePasswordSalt, func() (string, error) {
					return "password_salt", nil
				})

				monkey.Patch(passwordutils.HashPassword, func(password, salt string) (string, error) {
					return "", errors.New("error on HashPassword")
				})
			},
			httpReq:            httptest.NewRequest(http.MethodPost, "/users", strings.NewReader(`{"fullName": "Hansen", "phoneNumber": "+628111814032", "password": "p4ssw@rD"}`)),
			expectedStatusCode: http.StatusInternalServerError,
			expectedResponse: generated.ErrorResponse{
				Message: "Error creating user: failed to hash password",
			},
		},
		{
			name: "when failed create user on error conflict phone number CreateUserInput repo function",
			before: func() {
				monkey.Patch(passwordutils.GeneratePasswordSalt, func() (string, error) {
					return "password_salt", nil
				})

				monkey.Patch(passwordutils.HashPassword, func(password, salt string) (string, error) {
					return "password_hash", nil
				})

				mockRepo.
					EXPECT().
					CreateUser(
						context.Background(),
						repository.CreateUserInput{
							FullName:     "Hansen",
							PhoneNumber:  "+628111814032",
							PasswordHash: "password_hash",
							PasswordSalt: "password_salt",
						},
					).
					Return(repository.ErrDuplicateUserPhoneNumber).
					Times(1)
			},
			httpReq:            httptest.NewRequest(http.MethodPost, "/users", strings.NewReader(`{"fullName": "Hansen", "phoneNumber": "+628111814032", "password": "p4ssw@rD"}`)),
			expectedStatusCode: http.StatusConflict,
			expectedResponse: generated.ErrorResponse{
				Message: "Error creating user: Phone Number is already registered",
			},
		},
		{
			name: "when failed create user on error CreateUserInput repo function",
			before: func() {
				monkey.Patch(passwordutils.GeneratePasswordSalt, func() (string, error) {
					return "password_salt", nil
				})

				monkey.Patch(passwordutils.HashPassword, func(password, salt string) (string, error) {
					return "password_hash", nil
				})

				mockRepo.
					EXPECT().
					CreateUser(
						context.Background(),
						repository.CreateUserInput{
							FullName:     "Hansen",
							PhoneNumber:  "+628111814032",
							PasswordHash: "password_hash",
							PasswordSalt: "password_salt",
						},
					).
					Return(errors.New("error on CreateUserInput")).
					Times(1)
			},
			httpReq:            httptest.NewRequest(http.MethodPost, "/users", strings.NewReader(`{"fullName": "Hansen", "phoneNumber": "+628111814032", "password": "p4ssw@rD"}`)),
			expectedStatusCode: http.StatusInternalServerError,
			expectedResponse: generated.ErrorResponse{
				Message: "Error creating user: database error",
			},
		},
		{
			name: "when failed create user on error GetUserIdByPhoneNumber repo function",
			before: func() {
				monkey.Patch(passwordutils.GeneratePasswordSalt, func() (string, error) {
					return "password_salt", nil
				})

				monkey.Patch(passwordutils.HashPassword, func(password, salt string) (string, error) {
					return "password_hash", nil
				})

				mockRepo.
					EXPECT().
					CreateUser(
						context.Background(),
						repository.CreateUserInput{
							FullName:     "Hansen",
							PhoneNumber:  "+628111814032",
							PasswordHash: "password_hash",
							PasswordSalt: "password_salt",
						},
					).
					Return(nil).
					Times(1)

				mockRepo.
					EXPECT().
					GetUserIdByPhoneNumber(
						context.Background(),
						"+628111814032",
					).
					Return(uuid.Nil, errors.New("error on GetUserIdByPhoneNumber")).
					Times(1)
			},
			httpReq:            httptest.NewRequest(http.MethodPost, "/users", strings.NewReader(`{"fullName": "Hansen", "phoneNumber": "+628111814032", "password": "p4ssw@rD"}`)),
			expectedStatusCode: http.StatusInternalServerError,
			expectedResponse: generated.ErrorResponse{
				Message: "Error getting user ID: database error",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.before != nil {
				tc.before()
			}

			e := echo.New()
			req := tc.httpReq
			rec := httptest.NewRecorder()

			c := e.NewContext(req, rec)

			err := s.CreateUser(c)
			assert.NoError(t, err)

			assert.Equal(t, tc.expectedStatusCode, rec.Code)

			switch eRes := tc.expectedResponse.(type) {
			case generated.CreatedUserResponse:
				var response generated.CreatedUserResponse
				err = json.Unmarshal(rec.Body.Bytes(), &response)
				assert.Equal(t, eRes, response)
			case generated.ErrorResponse:
				var response generated.ErrorResponse
				err = json.Unmarshal(rec.Body.Bytes(), &response)
				assert.Equal(t, eRes, response)
			}
		})
	}
}

func Test_UserLogin(t *testing.T) {
	err := os.Setenv("JWT_SECRET_KEY", "dummy_key")
	assert.NoError(t, err)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := repository.NewMockRepositoryInterface(ctrl)
	s := NewServer(NewServerOptions{
		Repository: mockRepo,
	})

	userId := uuid.New()

	testCases := []struct {
		name               string
		before             func()
		httpReq            *http.Request
		expectedStatusCode int
		expectedResponse   any
	}{
		{
			name: "when successfully user login",
			before: func() {
				mockRepo.
					EXPECT().
					GetUserWithPasswordByPhoneNumber(context.Background(), "+628111814032").
					Return(repository.GetUserWithPasswordByPhoneNumberOutput{
						Id:           userId,
						PasswordHash: "$2a$10$yNs2OllfxTEiHjTcQq73me1./CwYltUSEEp5571.4Le3SfuaY0SMm",
						PasswordSalt: "password_salt",
					}, nil).
					Times(1)

				monkey.Patch(jwtutils.GenerateJWT, func(input jwtutils.GenerateJwtInput) (string, error) {
					return "jwt_token", nil
				})

				mockRepo.
					EXPECT().
					UserLogin(context.Background(), gomock.Any()).
					Return(nil).
					Times(1)
			},
			httpReq:            httptest.NewRequest(http.MethodPost, "/users/login", strings.NewReader(`{"phoneNumber": "+628111814032", "password": "p4ssw@rD"}`)),
			expectedStatusCode: http.StatusOK,
			expectedResponse: generated.UserLoginResponse{
				AccessToken: "Bearer jwt_token",
				UserId:      userId.String(),
			},
		},
		{
			name:               "when failed user login on read request body",
			before:             nil,
			httpReq:            httptest.NewRequest(http.MethodPost, "/users/login", &errorReaderCloser{}),
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse: generated.ErrorResponse{
				Message: validatorutlis.ErrReadRequestBody,
			},
		},
		{
			name:               "when failed user login on parse request body",
			before:             nil,
			httpReq:            httptest.NewRequest(http.MethodPost, "/users/login", nil),
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse: generated.ErrorResponse{
				Message: validatorutlis.ErrParseRequestBody,
			},
		},
		{
			name:               "when failed user login on validate",
			before:             nil,
			httpReq:            httptest.NewRequest(http.MethodPost, "/users/login", strings.NewReader(`{"phoneNumber": "", "password": ""}`)),
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse: generated.ErrorResponse{
				Message: "Validation failed",
				ValidationErrors: &[]struct {
					Field   string `json:"field"`
					Message string `json:"message"`
				}{
					{
						Field:   "phoneNumber",
						Message: "phone number must be between 10 and 13 characters and start with +62",
					},
					{
						Field:   "password",
						Message: "password must be between 6 and 64 characters",
					},
				},
			},
		},
		{
			name:               "when failed user login on invalid password format",
			before:             nil,
			httpReq:            httptest.NewRequest(http.MethodPost, "/users/login", strings.NewReader(`{"phoneNumber": "+628111814032", "password": "password"}`)),
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse: generated.ErrorResponse{
				Message: "Validation failed",
				ValidationErrors: &[]struct {
					Field   string `json:"field"`
					Message string `json:"message"`
				}{
					{
						Field:   "password",
						Message: "password must have at least 1 capital, 1 number, and 1 special character",
					},
				},
			},
		},
		{
			name: "when failed user login on error not found GetUserWithPasswordByPhoneNumber repo function",
			before: func() {
				mockRepo.
					EXPECT().
					GetUserWithPasswordByPhoneNumber(context.Background(), "+628111814032").
					Return(repository.GetUserWithPasswordByPhoneNumberOutput{}, repository.ErrRowNotFound).
					Times(1)
			},
			httpReq:            httptest.NewRequest(http.MethodPost, "/users/login", strings.NewReader(`{"phoneNumber": "+628111814032", "password": "p4ssw@rD"}`)),
			expectedStatusCode: http.StatusNotFound,
			expectedResponse: generated.ErrorResponse{
				Message: "User not found",
			},
		},
		{
			name: "when failed user login on error GetUserWithPasswordByPhoneNumber repo function",
			before: func() {
				mockRepo.
					EXPECT().
					GetUserWithPasswordByPhoneNumber(context.Background(), "+628111814032").
					Return(repository.GetUserWithPasswordByPhoneNumberOutput{}, errors.New("error on error GetUserWithPasswordByPhoneNumber")).
					Times(1)
			},
			httpReq:            httptest.NewRequest(http.MethodPost, "/users/login", strings.NewReader(`{"phoneNumber": "+628111814032", "password": "p4ssw@rD"}`)),
			expectedStatusCode: http.StatusInternalServerError,
			expectedResponse: generated.ErrorResponse{
				Message: "Error login: database error",
			},
		},
		{
			name: "when failed user login on incorrect password",
			before: func() {
				mockRepo.
					EXPECT().
					GetUserWithPasswordByPhoneNumber(context.Background(), "+628111814032").
					Return(repository.GetUserWithPasswordByPhoneNumberOutput{
						Id:           userId,
						PasswordHash: "$2a$10$yNs2OllfxTEiHjTcQq73me1",
						PasswordSalt: "password_salt",
					}, nil).
					Times(1)
			},
			httpReq:            httptest.NewRequest(http.MethodPost, "/users/login", strings.NewReader(`{"phoneNumber": "+628111814032", "password": "p4ssw@rD"}`)),
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse: generated.ErrorResponse{
				Message: "Incorrect password",
			},
		},
		{
			name: "when failed user login on generate jwt",
			before: func() {
				mockRepo.
					EXPECT().
					GetUserWithPasswordByPhoneNumber(context.Background(), "+628111814032").
					Return(repository.GetUserWithPasswordByPhoneNumberOutput{
						Id:           userId,
						PasswordHash: "$2a$10$yNs2OllfxTEiHjTcQq73me1./CwYltUSEEp5571.4Le3SfuaY0SMm",
						PasswordSalt: "password_salt",
					}, nil).
					Times(1)

				monkey.Patch(jwtutils.GenerateJWT, func(input jwtutils.GenerateJwtInput) (string, error) {
					return "", errors.New("error on GenerateJWT")
				})
			},
			httpReq:            httptest.NewRequest(http.MethodPost, "/users/login", strings.NewReader(`{"phoneNumber": "+628111814032", "password": "p4ssw@rD"}`)),
			expectedStatusCode: http.StatusInternalServerError,
			expectedResponse: generated.ErrorResponse{
				Message: "Error generating JWT",
			},
		},
		{
			name: "when failed user login on error UserLogin repo function",
			before: func() {
				mockRepo.
					EXPECT().
					GetUserWithPasswordByPhoneNumber(context.Background(), "+628111814032").
					Return(repository.GetUserWithPasswordByPhoneNumberOutput{
						Id:           userId,
						PasswordHash: "$2a$10$yNs2OllfxTEiHjTcQq73me1./CwYltUSEEp5571.4Le3SfuaY0SMm",
						PasswordSalt: "password_salt",
					}, nil).
					Times(1)

				monkey.Patch(jwtutils.GenerateJWT, func(input jwtutils.GenerateJwtInput) (string, error) {
					return "jwt_token", nil
				})

				mockRepo.
					EXPECT().
					UserLogin(context.Background(), gomock.Any()).
					Return(errors.New("error on UserLogin")).
					Times(1)
			},
			httpReq:            httptest.NewRequest(http.MethodPost, "/users/login", strings.NewReader(`{"phoneNumber": "+628111814032", "password": "p4ssw@rD"}`)),
			expectedStatusCode: http.StatusInternalServerError,
			expectedResponse: generated.ErrorResponse{
				Message: "Error login: database error",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.before != nil {
				tc.before()
			}

			e := echo.New()
			req := tc.httpReq
			rec := httptest.NewRecorder()

			c := e.NewContext(req, rec)

			err := s.UserLogin(c)
			assert.NoError(t, err)

			assert.Equal(t, tc.expectedStatusCode, rec.Code)

			switch eRes := tc.expectedResponse.(type) {
			case generated.UserLoginResponse:
				var response generated.UserLoginResponse
				err = json.Unmarshal(rec.Body.Bytes(), &response)
				assert.Equal(t, eRes, response)
			case generated.ErrorResponse:
				var response generated.ErrorResponse
				err = json.Unmarshal(rec.Body.Bytes(), &response)
				assert.Equal(t, eRes, response)
			}
		})
	}
}
