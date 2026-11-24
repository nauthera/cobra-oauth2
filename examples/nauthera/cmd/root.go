/*
Copyright © 2025 Michael Beutler

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

// Package cmd is a CLI for an API protected by nauthera-server. It uses
// what nauthera offers a command-line client: the browser flow with PKCE
// (pushed to /par when the server has it), the device flow over SSH,
// DPoP-bound tokens, refresh token rotation, resource indicators,
// revocation and RP-initiated logout on sign-out, and token exchange.
//
// Configure it with environment variables:
//
//	NAUTHERA_ISSUER     the issuer, e.g. https://auth.example.com or a
//	                    tenant issuer https://auth.example.com/orgs/acme
//	NAUTHERA_CLIENT_ID  a public client with the authorization_code,
//	                    device_code and refresh_token grants and the
//	                    loopback redirect URI http://127.0.0.1/callback
//	NAUTHERA_API        optional: the API's resource URI, e.g.
//	                    https://api.example.com. Tokens are then issued for
//	                    that API only (RFC 8707).
//
// Then:
//
//	nauthera auth login            # browser, or the device flow over SSH
//	nauthera auth status
//	nauthera get https://api.example.com/v1/me
//	nauthera exchange --audience billing
//	nauthera auth logout
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/nauthera/cobra-oauth2/pkg/auth"
	"github.com/nauthera/cobra-oauth2/pkg/storage"
)

// appName names the CLI in the keyring, the token directory and the
// User-Agent.
const appName = "nauthera-example"

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:          "nauthera",
	Short:        "Call an API protected by nauthera-server",
	SilenceUsage: true,
}

// Execute runs the root command. It is called by main.main.
func Execute() {
	if err := rootCmd.ExecuteContext(context.Background()); err != nil {
		os.Exit(1)
	}
}

// options are shared by every command. They do no I/O: discovery happens
// when a command runs, so --help works without a server.
func options() []auth.Option {
	opts := []auth.Option{
		// Sets the issuer and the openid and offline_access scopes;
		// nauthera issues a refresh token only with offline_access.
		auth.Nauthera(os.Getenv("NAUTHERA_ISSUER")),
		auth.WithClientID(os.Getenv("NAUTHERA_CLIENT_ID")),
		auth.WithAppName(appName),
		auth.WithStorage(tokenStore()),
		// Bind every token to a key only this CLI holds, whenever the
		// server advertises DPoP. A copied token is useless without the
		// key, and nauthera then binds the refresh token as well.
		auth.WithDPoPAuto(),
		// Keep the authorization request out of the browser's URL bar and
		// history whenever the server has a PAR endpoint, not only when it
		// requires one.
		auth.WithPAR(auth.PARIfAvailable),
		// On logout, after revoking the tokens, print the server's
		// end_session URL so the browser session ends too.
		auth.WithEndSession(auth.EndSessionOptions{}),
		auth.WithQRCode(true),
	}
	if api := os.Getenv("NAUTHERA_API"); api != "" {
		opts = append(opts, auth.WithResource(api))
	}
	return opts
}

// tokenStore keeps tokens in the system keyring and falls back to a 0600
// file under the user config directory where there is none, such as a
// container or an SSH session on a headless Linux host.
func tokenStore() storage.Provider {
	keyring := storage.NewKeyring("io.nauthera." + appName)
	dir, err := storage.DefaultFileDir(appName)
	if err != nil {
		return keyring
	}
	return storage.Fallback(keyring, storage.NewFile(dir))
}

// newClient builds a Client for a command of this CLI, with the same
// defaults the auth commands use.
func newClient(cmd *cobra.Command) (*auth.Client, error) {
	return auth.NewClientForCommand(cmd, options()...)
}

func init() {
	rootCmd.AddCommand(
		auth.NewAuthCommand(options()...),
		getCommand(),
		exchangeCommand(),
	)
}

// getCommand calls the API with the stored token. Client.Transport adds the
// Authorization header and, with DPoP, a fresh proof per request. It also
// refreshes the token when it expires and retries once when the server asks
// for a new DPoP nonce. The token goes only to the NAUTHERA_API origin when
// that is set (or to the URL's own origin otherwise), never to a host a
// redirect points to.
func getCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "get URL",
		Short: "GET an API URL with the stored access token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			u, err := url.Parse(args[0])
			if err != nil || u.Scheme != "https" || u.Host == "" {
				return fmt.Errorf("get: %q is not an https URL", args[0])
			}
			client, err := newClient(cmd)
			if err != nil {
				return err
			}
			hc := &http.Client{Transport: client.Transport(nil)}
			req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, u.String(), http.NoBody)
			if err != nil {
				return err
			}
			resp, err := hc.Do(req)
			if errors.Is(err, auth.ErrLoginRequired) {
				return fmt.Errorf("not signed in: run %q first", cmd.Root().Name()+" auth login")
			}
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode >= 300 {
				return fmt.Errorf("get: %s", resp.Status)
			}
			_, err = io.Copy(cmd.OutOrStdout(), io.LimitReader(resp.Body, 10<<20))
			return err
		},
	}
}

// exchangeCommand trades the CLI's access token for one meant for another
// service (RFC 8693), for example to hand a narrowly scoped token to a
// script. The client must be allowed the token exchange grant. The new
// token is printed, not stored.
func exchangeCommand() *cobra.Command {
	var audience, resource, scopes string
	cmd := &cobra.Command{
		Use:   "exchange",
		Short: "Exchange the stored access token for one for another service",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if audience == "" && resource == "" {
				return errors.New("exchange: set --audience or --resource")
			}
			client, err := newClient(cmd)
			if err != nil {
				return err
			}
			req := auth.ExchangeRequest{
				RequestedTokenType: auth.AccessTokenType,
				Scope:              strings.Fields(scopes),
			}
			if audience != "" {
				req.Audience = []string{audience}
			}
			if resource != "" {
				req.Resource = []string{resource}
			}
			res, err := client.ExchangeToken(cmd.Context(), req)
			if err != nil {
				return err
			}
			// stdout, so the token can be captured: TOKEN=$(nauthera exchange ...)
			_, err = fmt.Fprintln(cmd.OutOrStdout(), res.Token.AccessToken)
			return err
		},
	}
	cmd.Flags().StringVar(&audience, "audience", "", "the service the new token is for")
	cmd.Flags().StringVar(&resource, "resource", "", "the API the new token is for, as an absolute URI")
	cmd.Flags().StringVar(&scopes, "scopes", "", "space-separated scopes for the new token")
	return cmd
}
