// Package auth adds OAuth 2.0 and OpenID Connect sign-in to Cobra
// command-line applications.
//
// It provides ready-made commands ([NewAuthCommand], [NewLoginCommand],
// [NewLogoutCommand], [NewTokenCommand], [NewStatusCommand]) and the
// [Client] they are built on, which an application can also use directly,
// for example through [Client.Transport] to call its API.
//
// # Flows
//
//   - The authorization code grant with PKCE (S256) and a loopback redirect
//     on 127.0.0.1 (RFC 6749, RFC 7636, RFC 8252), with state, nonce and
//     RFC 9207 issuer checks. Selected with [FlowBrowser].
//   - The device authorization grant (RFC 8628) for sessions without a
//     browser, SSH and containers. Selected with [FlowDevice].
//   - The client credentials grant for confidential clients such as CI jobs.
//     Selected with [FlowClientCredentials].
//
// [FlowAuto], the default, uses the browser flow when a browser can be
// opened and the device flow otherwise.
//
// # Extensions
//
// Each of these is off unless an option or the provider's metadata turns
// it on:
//
//   - DPoP (RFC 9449) with [WithDPoP] or [WithDPoPAuto]: tokens bound to a
//     per-login key that is stored with them, a fresh proof on every token
//     and resource request, server nonces and clock skew handled with one
//     retry, and dpop_jkt binding of authorization codes and device codes.
//   - Pushed authorization requests (RFC 9126) with [WithPAR], and always
//     when the provider sets require_pushed_authorization_requests.
//   - private_key_jwt and client_secret_jwt client authentication
//     (RFC 7523) with [WithPrivateKeyJWT] and [ClientAuthSecretJWT].
//   - Resource indicators (RFC 8707) with [WithResource].
//   - Token exchange (RFC 8693) with [Client.ExchangeToken].
//   - Token introspection (RFC 7662) with [Client.Introspect], for
//     confidential clients.
//   - OpenID Connect RP-Initiated Logout with [WithEndSession].
//
// # Providers
//
// The client is provider-agnostic: give it an issuer with [WithIssuer] and
// it discovers the rest (OpenID Connect Discovery, RFC 8414), checking that
// the metadata names the same issuer. Providers without discovery are
// configured with explicit endpoints. Presets such as [GitHub], [Google],
// [EntraID], [Auth0], [Keycloak] and [Nauthera] capture the few settings
// that differ between providers.
//
// # Security
//
// Every endpoint must be https (loopback http is allowed for local
// development); back-channel requests never follow redirects; response
// bodies are size-limited; strings from the server are stripped of control
// characters before they reach a terminal; ID tokens are verified against
// the provider's JWKS with an asymmetric-only algorithm allowlist; tokens
// are stored per issuer, client and audience in the system keyring by
// default. The library never prints to the process's standard streams on
// its own: output goes to the writers given with [WithOutput], which the
// commands set to their own.
package auth
