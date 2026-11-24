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

// Package cmd is a small CLI for a confidential client, such as a CI job,
// that obtains tokens with the client credentials grant.
//
// Configure it with environment variables; never compile a client secret
// into a binary you distribute:
//
//	EXAMPLE_ISSUER         the issuer URL, e.g. https://auth.example.com
//	EXAMPLE_CLIENT_ID      a confidential client with the client_credentials grant
//	EXAMPLE_CLIENT_SECRET  its secret
//	EXAMPLE_SCOPES         optional, space-separated scopes to request
package cmd

import (
	"context"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/nauthera/cobra-oauth2/pkg/auth"
	"github.com/nauthera/cobra-oauth2/pkg/storage"
)

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:          "client-credentials",
	Short:        "Obtain access tokens with the client credentials grant",
	SilenceUsage: true,
}

// Execute runs the root command. It is called by main.main.
func Execute() {
	if err := rootCmd.ExecuteContext(context.Background()); err != nil {
		os.Exit(1)
	}
}

func init() {
	opts := []auth.Option{
		auth.WithIssuer(os.Getenv("EXAMPLE_ISSUER")),
		auth.WithClientID(os.Getenv("EXAMPLE_CLIENT_ID")),
		auth.WithClientSecret(os.Getenv("EXAMPLE_CLIENT_SECRET")),
		auth.WithFlow(auth.FlowClientCredentials),
		// A CI job has no keyring and needs no persistence: the token
		// command fetches a new token whenever the stored one is missing or
		// expired.
		auth.WithStorage(storage.NewMemory()),
	}
	if scopes := strings.Fields(os.Getenv("EXAMPLE_SCOPES")); len(scopes) > 0 {
		opts = append(opts, auth.WithScopes(scopes...))
	}
	rootCmd.AddCommand(
		auth.NewLoginCommand(opts...),
		auth.NewTokenCommand(opts...),
		auth.NewLogoutCommand(opts...),
	)
}
