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

// Package cmd is a small CLI that signs in to any OpenID Connect provider
// and calls its UserInfo endpoint with the
// access token.
//
// Configure it with environment variables:
//
//	EXAMPLE_ISSUER     the issuer URL, e.g. https://auth.example.com
//	EXAMPLE_CLIENT_ID  a public client registered with the device grant and
//	                   the loopback redirect URI http://127.0.0.1/callback
package cmd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	"github.com/nauthera/cobra-oauth2/pkg/auth"
)

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:          "basic",
	Short:        "Sign in with OAuth 2.0 / OpenID Connect and call an API",
	SilenceUsage: true,
}

// Execute runs the root command. It is called by main.main.
func Execute() {
	if err := rootCmd.ExecuteContext(context.Background()); err != nil {
		os.Exit(1)
	}
}

// options are shared by every command. They do no I/O: discovery happens
// when a command runs, so --help works offline.
func options() []auth.Option {
	return []auth.Option{
		auth.WithIssuer(os.Getenv("EXAMPLE_ISSUER")),
		// offline_access asks for a refresh token, so the CLI stays signed
		// in. A provider preset (auth.Nauthera, auth.Okta, ...) sets this.
		auth.WithScopes("openid", "offline_access"),
		auth.WithClientID(os.Getenv("EXAMPLE_CLIENT_ID")),
		auth.WithQRCode(true),
		// Bind the tokens to a key this CLI holds (DPoP) when the server
		// advertises it. A stolen token is then useless without the key.
		// The userinfo command below works either way: Client.Transport
		// adds the proofs.
		auth.WithDPoPAuto(),
	}
}

func init() {
	opts := options()

	// login, logout, token and status at the top level ...
	rootCmd.AddCommand(
		auth.NewLoginCommand(opts...),
		auth.NewLogoutCommand(opts...),
		auth.NewTokenCommand(opts...),
		auth.NewStatusCommand(opts...),
	)
	// ... or grouped under "auth": basic auth login.
	rootCmd.AddCommand(auth.NewAuthCommand(opts...))

	rootCmd.AddCommand(&cobra.Command{
		Use:   "userinfo",
		Short: "Call the provider's UserInfo endpoint with the stored token",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// The same defaults as the commands above, so this reads the
			// token the login command stored.
			client, err := auth.NewClientForCommand(cmd, opts...)
			if err != nil {
				return err
			}
			md, err := client.Metadata(cmd.Context())
			if err != nil {
				return err
			}
			if md.UserinfoEndpoint == "" {
				return fmt.Errorf("the provider has no userinfo endpoint")
			}
			// The transport adds the access token and refreshes it when
			// needed.
			hc := &http.Client{Transport: client.Transport(nil)}
			req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, md.UserinfoEndpoint, http.NoBody)
			if err != nil {
				return err
			}
			resp, err := hc.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("userinfo: %s", resp.Status)
			}
			_, err = io.Copy(cmd.OutOrStdout(), io.LimitReader(resp.Body, 1<<20))
			return err
		},
	})
}
