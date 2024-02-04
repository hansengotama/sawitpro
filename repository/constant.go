package repository

import "errors"

var ErrRowNotFound = errors.New("row not found")
var ErrNoUpdateNeeded = errors.New("no update needed")
var ErrDuplicateUserPhoneNumber = errors.New("pq: duplicate key value violates unique constraint \"users_phone_number_key\"")
