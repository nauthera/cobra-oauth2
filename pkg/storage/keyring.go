package storage

import (
	"errors"

	"github.com/golang-jwt/jwt"
	"github.com/zalando/go-keyring"
)

type keyringStorageProvider struct {
	service string
}

func NewKeyringStorage(service string) StorageProvider {
	return &keyringStorageProvider{service: service}
}

func (k *keyringStorageProvider) SetToken(token jwt.Token) error {
	if err := keyring.Set(k.service, k.service, token.Raw); err != nil {
		return errors.Join(ErrSetToken, err)
	}
	return nil
}

func (k *keyringStorageProvider) GetToken() (string, error) {
	token, err := keyring.Get(k.service, k.service)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return "", ErrTokenNotFound
		}
		return "", err
	}

	return token, nil
}

func (k *keyringStorageProvider) DeleteToken() error {
	return keyring.Delete(k.service, k.service)
}
