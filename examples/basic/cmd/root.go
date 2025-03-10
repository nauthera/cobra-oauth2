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
package cmd

import (
	"net/url"
	"os"

	"github.com/nauthera/cobra-oauth2/pkg/auth"
	"github.com/nauthera/cobra-oauth2/pkg/storage"
	"github.com/spf13/cobra"
)

const CLIENT_ID = "my-client-id"

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "cobra-oauth2",
	Short: "A simple CLI tool to demonstrate OAuth2 login and token retrieval.",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	discoveryUrl, err := url.Parse("https://foo-bar.nauthera.io/.well-known/openid-configuration")
	if err != nil {
		rootCmd.PrintErr("error parsing discovery URL: ", err)
		return
	}

	storageProvider := storage.NewKeyringStorage(CLIENT_ID)

	options := []auth.Option{
		auth.WithDiscoveryURL(*discoveryUrl),
		auth.WithClientID(CLIENT_ID),
		auth.WithStorageProvider(storageProvider),
	}

	rootCmd.AddCommand(
		auth.NewLoginCommand(options...),
		auth.NewTokenCommand(options...),
		auth.NewLogoutCommand(options...),
	)
}
