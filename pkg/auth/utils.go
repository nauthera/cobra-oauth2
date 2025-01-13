package auth

import "strings"

// joinScopes joins scopes into a single space-separated string.
func joinScopes(scopes []string) string {
	return strings.Join(scopes, " ")
}
