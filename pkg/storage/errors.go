package storage

import "errors"

var (
	ErrTokenNotFound = errors.New("no valid token found, try logging in again")
	ErrInvalidToken  = errors.New("invalid token")
	ErrDeleteToken   = errors.New("error deleting token")
	ErrSetToken      = errors.New("error setting token")
)
