package storage

import (
	"errors"
	"testing"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/zalando/go-keyring"
)

func TestGetToken(t *testing.T) {
	service := "testService"
	provider := &keyringStorageProvider{service: service}

	t.Run("Token found", func(t *testing.T) {
		expectedToken := "testToken"
		keyring.MockInit()
		keyring.Set(service, service, expectedToken)

		token, err := provider.GetToken()
		assert.NoError(t, err)
		assert.Equal(t, expectedToken, token)
	})

	t.Run("Token not found", func(t *testing.T) {
		keyring.MockInit()

		_, err := provider.GetToken()
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrTokenNotFound))
	})

	t.Run("Other error", func(t *testing.T) {
		expectedErr := errors.New("some error")
		keyring.MockInit()
		keyring.MockInitWithError(expectedErr)

		_, err := provider.GetToken()
		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
	})
}

func TestDeleteToken(t *testing.T) {
	service := "testService"
	provider := &keyringStorageProvider{service: service}

	t.Run("Delete token successfully", func(t *testing.T) {
		keyring.MockInit()
		keyring.Set(service, service, "testToken")

		err := provider.DeleteToken()
		assert.NoError(t, err)

		_, err = keyring.Get(service, service)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, keyring.ErrNotFound))
	})

	t.Run("Token not found", func(t *testing.T) {
		keyring.MockInit()

		err := provider.DeleteToken()
		assert.Error(t, err)
	})

	t.Run("Other error", func(t *testing.T) {
		expectedErr := errors.New("some error")
		keyring.MockInit()
		keyring.MockInitWithError(expectedErr)

		err := provider.DeleteToken()
		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
	})
}

func TestSetToken(t *testing.T) {
	service := "testService"
	provider := &keyringStorageProvider{service: service}

	t.Run("Set token successfully", func(t *testing.T) {
		keyring.MockInit()
		token := jwt.Token{Raw: "testToken"}

		err := provider.SetToken(token)
		assert.NoError(t, err)

		storedToken, err := keyring.Get(service, service)
		assert.NoError(t, err)
		assert.Equal(t, token.Raw, storedToken)
	})

	t.Run("Error setting token", func(t *testing.T) {
		expectedErr := errors.New("some error")
		keyring.MockInit()
		keyring.MockInitWithError(expectedErr)
		token := jwt.Token{Raw: "testToken"}

		err := provider.SetToken(token)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, expectedErr))
	})
}

func TestNewKeyringStorage(t *testing.T) {
	service := "testService"
	provider := NewKeyringStorage(service)

	assert.NotNil(t, provider)
	assert.IsType(t, &keyringStorageProvider{}, provider)
	assert.Equal(t, service, provider.(*keyringStorageProvider).service)
}
