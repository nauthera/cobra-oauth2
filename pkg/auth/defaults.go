package auth

import "time"

const (
	DefaultScopes  string        = "openid profile email"
	DefaultTimeout time.Duration = 2 * time.Minute
)
