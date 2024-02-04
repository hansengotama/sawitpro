package handler

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/hansengotama/sawitpro/generated"
	"github.com/hansengotama/sawitpro/repository"
	"github.com/hansengotama/sawitpro/utlis/passwordutils"
	"github.com/hansengotama/sawitpro/utlis/validatorutlis"
	"github.com/labstack/echo/v4"
	"github.com/procodr/monkey"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
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
		mock                func()
		authorizationHeader string
		expectedStatusCode  int
		expectedResponse    any
	}{
		{
			name: "when successfully get user",
			mock: func() {
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
			mock:                nil,
			authorizationHeader: "invalid",
			expectedStatusCode:  http.StatusForbidden,
			expectedResponse: generated.ErrorResponse{
				Message: "Invalid or Unauthorized Access",
			},
		},
		{
			name: "when failed get user on GetAccessTokenByToken repo function",
			mock: func() {
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
			mock: func() {
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
			mock: func() {
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
			if tc.mock != nil {
				tc.mock()
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
		mock                func()
		httpReq             *http.Request
		authorizationHeader string
		expectedStatusCode  int
		expectedResponse    any
	}{
		{
			name: "when successfully update user full name and phone number",
			mock: func() {
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
			mock: func() {
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
			mock: func() {
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
			mock:                nil,
			httpReq:             httptest.NewRequest(http.MethodPatch, "/users", nil),
			authorizationHeader: "invalid",
			expectedStatusCode:  http.StatusForbidden,
			expectedResponse: generated.ErrorResponse{
				Message: "Invalid or Unauthorized Access",
			},
		},
		{
			name: "when failed update user on GetAccessTokenByToken repo function",
			mock: func() {
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
			mock: func() {
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
			mock: func() {
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
			mock: func() {
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
			mock: func() {
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
			mock: func() {
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
			mock: func() {
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
			mock: func() {
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
			mock: func() {
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
			if tc.mock != nil {
				tc.mock()
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

	var patchGeneratePasswordSalt *monkey.PatchGuard
	var patchHashPassword *monkey.PatchGuard

	defer func() {
		if patchGeneratePasswordSalt != nil {
			patchGeneratePasswordSalt.Unpatch()
		}

		if patchHashPassword != nil {
			patchGeneratePasswordSalt.Unpatch()
		}
	}()

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
				patchGeneratePasswordSalt = monkey.Patch(passwordutils.GeneratePasswordSalt, func() (string, error) {
					return "password_salt", nil
				})

				patchHashPassword = monkey.Patch(passwordutils.HashPassword, func(password, salt string) (string, error) {
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
				patchGeneratePasswordSalt = monkey.Patch(passwordutils.GeneratePasswordSalt, func() (string, error) {
					return "", errors.New("error on GeneratePasswordSalt")
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
				patchGeneratePasswordSalt = monkey.Patch(passwordutils.GeneratePasswordSalt, func() (string, error) {
					return "password_salt", nil
				})

				patchHashPassword = monkey.Patch(passwordutils.HashPassword, func(password, salt string) (string, error) {
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
				patchGeneratePasswordSalt = monkey.Patch(passwordutils.GeneratePasswordSalt, func() (string, error) {
					return "password_salt", nil
				})

				patchHashPassword = monkey.Patch(passwordutils.HashPassword, func(password, salt string) (string, error) {
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
				patchGeneratePasswordSalt = monkey.Patch(passwordutils.GeneratePasswordSalt, func() (string, error) {
					return "password_salt", nil
				})

				patchHashPassword = monkey.Patch(passwordutils.HashPassword, func(password, salt string) (string, error) {
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
				patchGeneratePasswordSalt = monkey.Patch(passwordutils.GeneratePasswordSalt, func() (string, error) {
					return "password_salt", nil
				})

				patchHashPassword = monkey.Patch(passwordutils.HashPassword, func(password, salt string) (string, error) {
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

}
