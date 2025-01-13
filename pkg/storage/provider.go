package storage

import "github.com/golang-jwt/jwt"

type StorageProvider interface {
	SetToken(token jwt.Token) error
	GetToken() (string, error)
	DeleteToken() error
}
