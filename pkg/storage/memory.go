package storage

import (
	"sync"

	"github.com/golang-jwt/jwt"
)

// In-memory storage provider for testing purposes.
// Uses a mutex to be thread-safe.
type memoryStorageProvider struct {
	service string
	mutex   sync.Mutex
	token   string
}

func NewMemoryStorage(service string) StorageProvider {
	return &memoryStorageProvider{
		mutex:   sync.Mutex{},
		service: service,
		token:   "",
	}
}

// DeleteToken implements StorageProvider.
func (m *memoryStorageProvider) DeleteToken() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.token = ""
	return nil
}

// GetToken implements StorageProvider.
func (m *memoryStorageProvider) GetToken() (string, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if m.token != "" {
		return m.token, nil
	}
	return "", ErrTokenNotFound
}

// SetToken implements StorageProvider.
func (m *memoryStorageProvider) SetToken(token jwt.Token) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.token = token.Raw
	return nil
}
