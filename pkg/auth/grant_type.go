package auth

type GrantType string

const (
	AuthorizationCode GrantType = "authorization_code"
	ClientCredentials GrantType = "client_credentials"
	DeviceCode        GrantType = "urn:ietf:params:oauth:grant-type:device_code"
	Password          GrantType = "password"
	RefreshToken      GrantType = "refresh_token"
)

func (g GrantType) String() string {
	return string(g)
}
