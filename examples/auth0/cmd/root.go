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

// Package cmd is a CLI that signs in to Auth0 and calls an API with the
// access token. Configure it with environment variables:
//
//	AUTH0_DOMAIN         the tenant domain, e.g. example.eu.auth0.com, or a
//	                     custom domain
//	AUTH0_CLIENT_ID      the application's client ID
//	AUTH0_AUDIENCE       the identifier of the API the tokens are for; without
//	                     it Auth0 issues a token that only works at /userinfo
//	AUTH0_CLIENT_SECRET  optional: set it for a Machine to Machine
//	                     application, and the CLI uses the client credentials
//	                     grant instead of signing a person in
//	AUTH0_REDIRECT_PORT  optional: the loopback port of the browser flow's
//	                     callback, default 8484. Auth0 matches it exactly, so
//	                     register http://127.0.0.1:<port>/callback.
//
// README.md next to main.go says how to set up the applications in Auth0.
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/nauthera/cobra-oauth2/pkg/auth"
	"github.com/nauthera/cobra-oauth2/pkg/storage"
)

// defaultRedirectPort is the browser flow's callback port when
// AUTH0_REDIRECT_PORT is not set.
const defaultRedirectPort = 8484

// Execute runs the CLI. It is called by main.main.
func Execute() {
	if err := NewRootCommand(os.Getenv).ExecuteContext(context.Background()); err != nil {
		os.Exit(1)
	}
}

// NewRootCommand builds the CLI from getenv (os.Getenv in main). extra
// options are appended to the ones the environment sets; the tests use them
// to point the CLI at a fake Auth0.
func NewRootCommand(getenv func(string) string, extra ...auth.Option) *cobra.Command {
	opts := append(options(getenv), extra...)
	root := &cobra.Command{
		Use:          "auth0-example",
		Short:        "Sign in to Auth0 and call an API",
		SilenceUsage: true,
	}
	root.AddCommand(auth.NewAuthCommand(opts...), getCommand(opts))
	return root
}

// options maps the environment to the library's options. They do no I/O:
// discovery happens when a command runs, so --help works offline.
func options(getenv func(string) string) []auth.Option {
	opts := []auth.Option{
		// Sets the issuer with the trailing slash Auth0 publishes, the
		// audience, and the openid, profile and offline_access scopes.
		auth.Auth0(getenv("AUTH0_DOMAIN"), getenv("AUTH0_AUDIENCE")),
		auth.WithClientID(getenv("AUTH0_CLIENT_ID")),
	}
	if secret := getenv("AUTH0_CLIENT_SECRET"); secret != "" {
		// A Machine to Machine application: no person, no browser, no
		// refresh token. Nothing to keep between runs either; the token
		// command fetches a new token whenever the last one has expired.
		return append(opts,
			auth.WithClientSecret(secret),
			auth.WithFlow(auth.FlowClientCredentials),
			auth.WithStorage(storage.NewMemory()),
		)
	}
	port := defaultRedirectPort
	if p, err := strconv.Atoi(getenv("AUTH0_REDIRECT_PORT")); err == nil {
		port = p
	}
	return append(opts,
		auth.WithRedirectPort(port),
		auth.WithQRCode(true),
	)
}

// getCommand calls the API with the stored access token. Client.Transport
// adds the Authorization header, refreshes an expired token, and sends the
// token to the URL's origin only.
func getCommand(opts []auth.Option) *cobra.Command {
	return &cobra.Command{
		Use:   "get URL",
		Short: "GET an API URL with the stored access token",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			u, err := url.Parse(args[0])
			if err != nil || u.Scheme != "https" || u.Host == "" {
				return fmt.Errorf("get: %q is not an https URL", args[0])
			}
			client, err := auth.NewClientForCommand(cmd, opts...)
			if err != nil {
				return err
			}
			hc := &http.Client{Transport: client.Transport(nil)}
			req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, u.String(), http.NoBody)
			if err != nil {
				return err
			}
			resp, err := hc.Do(req)
			if errors.Is(err, auth.ErrLoginRequired) || errors.Is(err, auth.ErrNotLoggedIn) {
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
