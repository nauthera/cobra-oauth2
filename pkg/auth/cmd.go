package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// NewAuthCommand returns an "auth" command grouping the login, logout,
// token and status commands, all configured with opts:
//
//	rootCmd.AddCommand(auth.NewAuthCommand(
//		auth.WithIssuer("https://auth.example.com"),
//		auth.WithClientID("my-cli"),
//	))
func NewAuthCommand(opts ...Option) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Sign in, sign out and print access tokens",
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(
		NewLoginCommand(opts...),
		NewLogoutCommand(opts...),
		NewTokenCommand(opts...),
		NewStatusCommand(opts...),
	)
	return cmd
}

// NewClientForCommand returns a Client set up the way the login, logout,
// token and status commands set up theirs: messages go to cmd's output and
// error writers, and the keyring service defaults to the root command's
// name. opts apply after those defaults, so an app name pinned with
// [WithAppName] wins. Use it in your own commands to call an API with the
// token the login command stored:
//
//	client, err := auth.NewClientForCommand(cmd, opts...)
//	if err != nil {
//		return err
//	}
//	hc := &http.Client{Transport: client.Transport(nil)}
func NewClientForCommand(cmd *cobra.Command, opts ...Option) (*Client, error) {
	return clientFor(cmd, opts)
}

// clientFor builds the Client for one command invocation: output goes to
// the command's writers and the keyring service defaults to the root
// command's name, then the caller's options apply, then the flags'. It
// copies the options, so the caller's slice is never written to.
func clientFor(cmd *cobra.Command, opts []Option, flagOpts ...Option) (*Client, error) {
	all := make([]Option, 0, len(opts)+len(flagOpts)+2)
	all = append(all, WithAppName(cmd.Root().Name()), WithOutput(cmd.OutOrStdout(), cmd.ErrOrStderr()))
	all = append(all, opts...)
	all = append(all, flagOpts...)
	return NewClient(all...)
}

func commandContext(cmd *cobra.Command) context.Context {
	if ctx := cmd.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}

// NewLoginCommand returns a "login" command that signs the user in with the
// configured flow and stores the tokens. Its flags choose the flow
// (--flow), suppress the browser (--no-browser), replace the scopes
// (--scopes) and print a QR code in the device flow (--qr).
func NewLoginCommand(opts ...Option) *cobra.Command {
	var (
		flow      string
		noBrowser bool
		qr        bool
		scopes    []string
	)
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Sign in and store the tokens",
		Long: `Sign in with your identity provider and store the tokens.

By default a browser is opened for the sign-in when one is available, and
the device flow is used otherwise: you open a page on any device and enter
the code shown here. Use --flow to choose explicitly.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true
			var flagOpts []Option
			if flow != "" {
				flagOpts = append(flagOpts, WithFlow(Flow(flow)))
			}
			if noBrowser {
				flagOpts = append(flagOpts, WithBrowser(false))
			}
			if qr {
				flagOpts = append(flagOpts, WithQRCode(true))
			}
			if cmd.Flags().Changed("scopes") {
				flagOpts = append(flagOpts, WithScopes(scopes...))
			}
			c, err := clientFor(cmd, opts, flagOpts...)
			if err != nil {
				return err
			}
			tok, err := c.Login(commandContext(cmd))
			if err != nil {
				return fmt.Errorf("login: %w", err)
			}
			w := cmd.ErrOrStderr()
			who := ""
			if st, err := c.Status(commandContext(cmd)); err == nil {
				who = identity(st)
			}
			if who != "" {
				_, _ = fmt.Fprintf(w, "Logged in to %s as %s.\n", c.Issuer(), who)
			} else {
				_, _ = fmt.Fprintf(w, "Logged in to %s.\n", c.Issuer())
			}
			if !tok.Expiry.IsZero() {
				_, _ = fmt.Fprintf(w, "The access token expires in %s.\n", humanDuration(tok.Expiry.Sub(c.now())))
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&flow, "flow", "", "login flow: auto, device, browser or client-credentials")
	f.BoolVar(&noBrowser, "no-browser", false, "do not open a browser; print the URL instead")
	f.BoolVar(&qr, "qr", false, "print a QR code of the verification URL (device flow)")
	f.StringSliceVar(&scopes, "scopes", nil, "scopes to request, replacing the defaults (comma-separated)")
	return cmd
}

// NewLogoutCommand returns a "logout" command that revokes the stored
// tokens at the server, when it supports revocation, and deletes them.
// With [WithEndSession] it also opens the provider's sign-out page, or only
// prints its URL with --no-browser.
func NewLogoutCommand(opts ...Option) *cobra.Command {
	var noBrowser bool
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Revoke and delete the stored tokens",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true
			var flagOpts []Option
			if noBrowser {
				flagOpts = append(flagOpts, WithBrowser(false))
			}
			c, err := clientFor(cmd, opts, flagOpts...)
			if err != nil {
				return err
			}
			w := cmd.ErrOrStderr()
			err = c.Logout(commandContext(cmd))
			switch {
			case err == nil:
				_, _ = fmt.Fprintln(w, "Logged out.")
				return nil
			case errors.Is(err, ErrNotLoggedIn):
				_, _ = fmt.Fprintln(w, "Not logged in.")
				return nil
			case errors.Is(err, ErrRevocationFailed):
				_, _ = fmt.Fprintf(w, "Warning: %v\n", err)
				_, _ = fmt.Fprintln(w, "Logged out locally; the server may still accept the tokens until they expire.")
				return nil
			default:
				return fmt.Errorf("logout: %w", err)
			}
		},
	}
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false,
		"do not open the provider's sign-out page; print its URL instead (with WithEndSession)")
	return cmd
}

type tokenJSON struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	Expiry      time.Time `json:"expiry,omitzero"`
	Scope       string    `json:"scope,omitempty"`
	Issuer      string    `json:"issuer"`
}

// NewTokenCommand returns a "token" command that prints a valid access
// token, refreshed when needed, and nothing else, to standard output:
// TOKEN=$(mycli token). With --json it prints the token with its type,
// expiry, scope and issuer; refresh and ID tokens are never printed.
func NewTokenCommand(opts ...Option) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Print a valid access token",
		Long: `Print a valid access token to standard output, refreshing it first when it
has expired, so that scripts can use it:

    curl -H "Authorization: Bearer $(mycli token)" https://api.example.com/`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true
			c, err := clientFor(cmd, opts)
			if err != nil {
				return err
			}
			tok, err := c.Token(commandContext(cmd))
			if err != nil {
				return fmt.Errorf("token: %w", err)
			}
			out := cmd.OutOrStdout()
			if !asJSON {
				if tok.TokenType == TokenTypeDPoP {
					_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "Note: this token is DPoP-bound; a server accepts it only with a DPoP proof "+
						"from this client's key, not as a Bearer token.")
				}
				_, err = fmt.Fprintln(out, tok.AccessToken)
				return err
			}
			return writeJSON(out, tokenJSON{
				AccessToken: tok.AccessToken,
				TokenType:   tok.TokenType,
				Expiry:      tok.Expiry,
				Scope:       tok.Scope,
				Issuer:      tok.Issuer,
			})
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the access token with its metadata as JSON")
	return cmd
}

// NewStatusCommand returns a "status" command that shows whether a token
// set is stored, for whom and until when, without printing any token. It
// fails when not logged in, so scripts can test `mycli status`.
func NewStatusCommand(opts ...Option) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the signed-in account and token expiry",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true
			c, err := clientFor(cmd, opts)
			if err != nil {
				return err
			}
			st, err := c.Status(commandContext(cmd))
			if err != nil {
				return fmt.Errorf("status: %w", err)
			}
			out := cmd.OutOrStdout()
			if asJSON {
				return writeJSON(out, st)
			}
			return writeStatus(out, st, c.now())
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the status as JSON")
	return cmd
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("write JSON: %w", err)
	}
	return nil
}

func identity(st *Status) string {
	switch {
	case st.Email != "":
		return st.Email
	case st.Name != "":
		return st.Name
	default:
		return st.Subject
	}
}

func writeStatus(w io.Writer, st *Status, now time.Time) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Logged in to %s\n", st.Issuer)
	if who := identity(st); who != "" {
		if st.Subject != "" && who != st.Subject {
			who += " (subject " + st.Subject + ")"
		}
		fmt.Fprintf(&b, "  Account:       %s\n", who)
	}
	fmt.Fprintf(&b, "  Client ID:     %s\n", st.ClientID)
	fmt.Fprintf(&b, "  Token type:    %s\n", st.TokenType)
	if st.Scope != "" {
		fmt.Fprintf(&b, "  Scopes:        %s\n", st.Scope)
	}
	switch {
	case st.Expiry.IsZero():
		fmt.Fprintf(&b, "  Access token:  no expiry given by the server\n")
	case st.Expired:
		next := "log in again"
		if st.HasRefreshToken {
			next = "it is refreshed on next use"
		}
		fmt.Fprintf(&b, "  Access token:  expired %s ago; %s\n", humanDuration(now.Sub(st.Expiry)), next)
	default:
		fmt.Fprintf(&b, "  Access token:  valid for %s (until %s)\n", humanDuration(st.Expiry.Sub(now)), st.Expiry.Local().Format(time.RFC1123))
	}
	refresh := "no"
	if st.HasRefreshToken {
		refresh = "yes"
	}
	fmt.Fprintf(&b, "  Refresh token: %s\n", refresh)
	_, err := io.WriteString(w, b.String())
	return err
}

// humanDuration rounds d for display: "42s", "9m", "3h5m".
func humanDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	switch {
	case d < time.Minute:
		return d.Round(time.Second).String()
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Round(time.Minute).Minutes()))
	default:
		d = d.Round(time.Minute)
		h := int(d.Hours())
		m := int(d.Minutes()) - h*60
		if m == 0 {
			return fmt.Sprintf("%dh", h)
		}
		return fmt.Sprintf("%dh%dm", h, m)
	}
}
