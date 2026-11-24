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

// Package cmd signs in to GitHub with the device flow. GitHub has no
// discovery document; the GitHub preset supplies its endpoints.
//
//	EXAMPLE_GITHUB_CLIENT_ID  the client ID of a GitHub App or OAuth App
//	                          with "Enable Device Flow" switched on
package cmd

import (
	"context"
	"os"

	"github.com/spf13/cobra"

	"github.com/nauthera/cobra-oauth2/pkg/auth"
)

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:          "github-example",
	Short:        "Sign in to GitHub with the device flow",
	SilenceUsage: true,
}

// Execute runs the root command. It is called by main.main.
func Execute() {
	if err := rootCmd.ExecuteContext(context.Background()); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.AddCommand(auth.NewAuthCommand(
		auth.GitHub(),
		auth.WithClientID(os.Getenv("EXAMPLE_GITHUB_CLIENT_ID")),
		auth.WithFlow(auth.FlowDevice),
		auth.WithScopes("read:user"),
	))
}
