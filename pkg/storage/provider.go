package storage

import "github.com/golang-jwt/jwt"

// StorageProvider defines an interface for managing JWT tokens in a storage system.
// Implementations of this interface should provide mechanisms to set, retrieve, and delete tokens.
type StorageProvider interface {
	SetToken(token jwt.Token) error
	GetToken() (string, error)
	DeleteToken() error
}
