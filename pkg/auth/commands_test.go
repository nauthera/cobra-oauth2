package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/nauthera/cobra-oauth2/internal/oauthtest"
	"github.com/nauthera/cobra-oauth2/pkg/auth"
)

// cli is a root command with the auth commands, wired to an env the way an
// importer wires them, minus the output: the commands write to the cobra
// command's own writers.
type cli struct {
	e    *env
	opts []auth.Option
}

func newCLI(t *testing.T, e *env, opts ...auth.Option) *cli {
	t.Helper()
	return &cli{e: e, opts: append([]auth.Option{
		auth.Nauthera(e.as.Issuer()), auth.WithClientID(nautheraCLI),
		auth.WithHTTPClient(e.as.Client()), auth.WithStorage(e.store), auth.WithClock(e.clock), auth.WithBrowser(false),
	}, opts...)}
}

func (c *cli) run(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	root := &cobra.Command{Use: "mycli", SilenceErrors: true}
	root.AddCommand(auth.NewAuthCommand(c.opts...))
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(args)
	err = root.ExecuteContext(t.Context())
	return out.String(), errOut.String(), err
}

func (c *cli) mustRun(t *testing.T, args ...string) (stdout, stderr string) {
	t.Helper()
	stdout, stderr, err := c.run(t, args...)
	if err != nil {
		t.Fatalf("mycli %s: %v\nstderr: %s", strings.Join(args, " "), err, stderr)
	}
	return stdout, stderr
}

func nautheraCLIEnv(t *testing.T, mutate func(*oauthtest.Config)) *env {
	t.Helper()
	cfg := nautheraConfig(t, "discovery.json")
	cfg.IDTokenClaims = map[string]any{"email": "user@example.com"}
	if mutate != nil {
		mutate(&cfg)
	}
	return newEnv(t, cfg, nil)
}

func TestCLILifecycle(t *testing.T) {
	t.Parallel()
	e := nautheraCLIEnv(t, nil)
	c := newCLI(t, e)

	stdout, stderr := c.mustRun(t, "auth", "login", "--flow", "device")
	if stdout != "" {
		t.Fatalf("login wrote to stdout: %q", stdout)
	}
	for _, want := range []string{"WDJB-MJHT", e.as.Issuer() + "/device", "Logged in to " + e.as.Issuer() + " as user@example.com", "expires in 10m"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("login stderr lacks %q:\n%s", want, stderr)
		}
	}
	stored, err := e.store.Get(t.Context(), c.client(t).StorageKey())
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecret(t, "login output", stdout+stderr, stored.AccessToken, stored.RefreshToken, stored.IDToken)

	// token prints the access token and nothing else, so $(mycli token)
	// works.
	stdout, stderr = c.mustRun(t, "auth", "token")
	if stdout != stored.AccessToken+"\n" || stderr != "" {
		t.Fatalf("token: stdout %q stderr %q", stdout, stderr)
	}

	stdout, _ = c.mustRun(t, "auth", "token", "--json")
	var tj map[string]any
	if err := json.Unmarshal([]byte(stdout), &tj); err != nil {
		t.Fatalf("token --json: %v\n%s", err, stdout)
	}
	if tj["access_token"] != stored.AccessToken || tj["token_type"] != "Bearer" || tj["issuer"] != e.as.Issuer() {
		t.Fatalf("token --json: %v", tj)
	}
	if _, ok := tj["refresh_token"]; ok {
		t.Fatal("token --json printed the refresh token")
	}
	assertNoSecret(t, "token --json", stdout, stored.RefreshToken, stored.IDToken)

	stdout, _ = c.mustRun(t, "auth", "status", "--json")
	var st auth.Status
	if err := json.Unmarshal([]byte(stdout), &st); err != nil {
		t.Fatal(err)
	}
	if st.Subject != "user-1" || st.Email != "user@example.com" || !st.HasRefreshToken || st.Expired || st.ClientID != nautheraCLI {
		t.Fatalf("status --json: %+v", st)
	}
	stdout, _ = c.mustRun(t, "auth", "status")
	if !strings.Contains(stdout, "valid for 10m") || !strings.Contains(stdout, "user@example.com (subject user-1)") {
		t.Fatalf("status:\n%s", stdout)
	}
	assertNoSecret(t, "status", stdout, stored.AccessToken, stored.RefreshToken)

	// After expiry, token refreshes (rotating the refresh token) and still
	// prints only the token.
	e.clock.Advance(11 * time.Minute)
	stdout, _ = c.mustRun(t, "auth", "status")
	if !strings.Contains(stdout, "expired 1m ago; it is refreshed on next use") {
		t.Fatalf("status after expiry:\n%s", stdout)
	}
	stdout, stderr = c.mustRun(t, "auth", "token")
	refreshed, _ := e.store.Get(t.Context(), c.client(t).StorageKey())
	if stdout != refreshed.AccessToken+"\n" || refreshed.AccessToken == stored.AccessToken || stderr != "" {
		t.Fatalf("token after expiry: %q (stored %v)", stdout, refreshed)
	}

	_, stderr = c.mustRun(t, "auth", "logout")
	if !strings.Contains(stderr, "Logged out.") || !e.as.Revoked(refreshed.RefreshToken) {
		t.Fatalf("logout: %q", stderr)
	}
	if _, _, err := c.run(t, "auth", "status"); !errors.Is(err, auth.ErrNotLoggedIn) {
		t.Fatalf("status after logout: %v", err)
	}
	if stdout, _, err := c.run(t, "auth", "token"); !errors.Is(err, auth.ErrNotLoggedIn) || stdout != "" {
		t.Fatalf("token after logout: %q %v", stdout, err)
	}
	_, stderr = c.mustRun(t, "auth", "logout")
	if !strings.Contains(stderr, "Not logged in.") {
		t.Fatalf("second logout: %q", stderr)
	}
}

// client builds the Client the commands build, for its storage key.
func (c *cli) client(t *testing.T) *auth.Client {
	t.Helper()
	cl, err := auth.NewClient(append([]auth.Option{auth.WithAppName("mycli")}, c.opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return cl
}

func TestCLIBrowserLogin(t *testing.T) {
	t.Parallel()
	e := nautheraCLIEnv(t, nil)
	c := newCLI(t, e, auth.WithBrowser(true), auth.WithBrowserOpener(e.as.OpenBrowser))
	stdout, stderr := c.mustRun(t, "auth", "login")
	if stdout != "" || !strings.Contains(stderr, "Opened your browser") || !strings.Contains(stderr, "Logged in to") {
		t.Fatalf("login: stdout %q stderr %q", stdout, stderr)
	}
	if n := len(e.as.Requests(oauthtest.EndpointDeviceAuthorization)); n != 0 {
		t.Fatal("auto flow with a browser must use the browser flow")
	}

	// --no-browser: the auto flow falls back to the device flow.
	c2 := newCLI(t, e, auth.WithBrowserOpener(func(_ context.Context, _ string) error {
		t.Error("browser opened despite --no-browser")
		return nil
	}))
	_, stderr = c2.mustRun(t, "auth", "login", "--no-browser")
	if !strings.Contains(stderr, "WDJB-MJHT") {
		t.Fatalf("login --no-browser did not use the device flow:\n%s", stderr)
	}
}

func TestCLILoginFlags(t *testing.T) {
	t.Parallel()
	e := nautheraCLIEnv(t, nil)
	c := newCLI(t, e)
	_, stderr := c.mustRun(t, "auth", "login", "--flow", "device", "--scopes", "openid,email", "--qr")
	if !strings.Contains(stderr, "QR code") {
		t.Fatalf("--qr printed no QR code:\n%s", stderr)
	}
	if got := e.as.Requests(oauthtest.EndpointDeviceAuthorization)[0].Form.Get("scope"); got != "openid email" {
		t.Fatalf("--scopes: scope = %q", got)
	}
	stdout, _ := c.mustRun(t, "auth", "status")
	if !strings.Contains(stdout, "Refresh token: no") {
		t.Fatalf("without offline_access there is no refresh token:\n%s", stdout)
	}
	if _, _, err := c.run(t, "auth", "login", "--flow", "implicit"); !errors.Is(err, auth.ErrInvalidConfig) {
		t.Fatalf("--flow implicit: %v", err)
	}
	if _, _, err := c.run(t, "auth", "token", "extra-arg"); err == nil {
		t.Fatal("token accepted a positional argument")
	}
}

func TestCLILogoutWarnsWhenRevocationFails(t *testing.T) {
	t.Parallel()
	e := nautheraCLIEnv(t, nil)
	c := newCLI(t, e)
	c.mustRun(t, "auth", "login", "--flow", "device")
	e.as.Override(oauthtest.EndpointRevocation, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	_, stderr, err := c.run(t, "auth", "logout")
	if err != nil || !strings.Contains(stderr, "Warning:") || !strings.Contains(stderr, "Logged out locally") {
		t.Fatalf("logout: %v\n%s", err, stderr)
	}
	if _, _, err := c.run(t, "auth", "status"); !errors.Is(err, auth.ErrNotLoggedIn) {
		t.Fatal("the local tokens must be gone after a failed revocation")
	}
}

func TestCLITokenNotesDPoPBinding(t *testing.T) {
	t.Parallel()
	e := nautheraCLIEnv(t, nil)
	c := newCLI(t, e, auth.WithDPoP())
	c.mustRun(t, "auth", "login", "--flow", "device")
	stdout, stderr := c.mustRun(t, "auth", "token")
	if strings.Count(stdout, "\n") != 1 || !strings.HasPrefix(stdout, "at-") || !strings.Contains(stderr, "DPoP-bound") {
		t.Fatalf("token: stdout %q stderr %q", stdout, stderr)
	}
	stdout, _ = c.mustRun(t, "auth", "token", "--json")
	if !strings.Contains(stdout, `"token_type": "DPoP"`) {
		t.Fatalf("token --json: %s", stdout)
	}
}

func TestCLIStatusWithoutIdentity(t *testing.T) {
	t.Parallel()
	e := nautheraCLIEnv(t, nil)
	svc := newCLI(t, e, auth.WithClientID(nautheraService), auth.WithClientSecret(nautheraServiceSecret),
		auth.WithFlow(auth.FlowClientCredentials))
	_, stderr := svc.mustRun(t, "auth", "login")
	if !strings.Contains(stderr, "Logged in to "+e.as.Issuer()+".") {
		t.Fatalf("login without an ID token:\n%s", stderr)
	}
	stdout, _ := svc.mustRun(t, "auth", "status")
	if strings.Contains(stdout, "Account:") || !strings.Contains(stdout, "Refresh token: no") {
		t.Fatalf("status:\n%s", stdout)
	}
}
