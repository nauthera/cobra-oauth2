package storage

import (
	"testing"

	"github.com/golang-jwt/jwt"
	"github.com/stretchr/testify/assert"
)

func TestMemoryStorageProvider(t *testing.T) {
	provider := NewMemoryStorage("test")

	const tokenString = "testToken"

	// Test SetToken
	token := jwt.Token{Raw: tokenString}
	assert.NotEmpty(t, token.Raw)

	err := provider.SetToken(token)
	assert.NoError(t, err)

	// Test GetToken
	retrievedToken, err := provider.GetToken()
	assert.NoError(t, err)
	assert.Equal(t, tokenString, retrievedToken)

	// Test DeleteToken
	err = provider.DeleteToken()
	assert.NoError(t, err)

	// Test GetToken after deletion
	retrievedToken, err = provider.GetToken()
	assert.Error(t, err)
	assert.Equal(t, "", retrievedToken)
}
