package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/nauthera/cobra-oauth2/pkg/storage"
)

// recordingStore wraps a memory provider and records which methods ran,
// so the tests can tell the configured provider is the one being used.
type recordingStore struct {
	storage.Provider
	mu    sync.Mutex
	calls []string
}

func newRecordingStore() *recordingStore { return &recordingStore{Provider: storage.NewMemory()} }

func (r *recordingStore) record(op string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, op)
}

func (r *recordingStore) Get(ctx context.Context, k storage.Key) (*storage.Token, error) {
	r.record("get")
	return r.Provider.Get(ctx, k)
}

func (r *recordingStore) Set(ctx context.Context, k storage.Key, t *storage.Token) error {
	r.record("set")
	return r.Provider.Set(ctx, k, t)
}

func (r *recordingStore) Delete(ctx context.Context, k storage.Key) error {
	r.record("delete")
	return r.Provider.Delete(ctx, k)
}

func (r *recordingStore) has(op string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.calls {
		if c == op {
			return true
		}
	}
	return false
}

func runCommand(t *testing.T, cmd *cobra.Command, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	root := &cobra.Command{Use: "mycli", SilenceErrors: true}
	root.AddCommand(cmd)
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(append([]string{cmd.Name()}, args...))
	err = root.ExecuteContext(context.Background())
	return out.String(), errOut.String(), err
}

func ccServer(t *testing.T) *fakeAS {
	t.Helper()
	as := newFakeAS(t)
	as.handle("/token", func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(w, 200, map[string]any{"access_token": "cmd-access-token", "token_type": "Bearer", "expires_in": 3600})
	})
	as.handle("/revoke", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	return as
}

func cmdOptions(as *fakeAS, store storage.Provider, extra ...Option) []Option {
	return append([]Option{
		WithIssuer(as.URL), WithClientID(testClientID), WithClientSecret("cmd-client-secret"),
		WithFlow(FlowClientCredentials), WithStorage(store), WithHTTPClient(as.Client()), WithBrowser(false),
	}, extra...)
}

func TestCommandsUseConfiguredStorage(t *testing.T) {
	t.Parallel()
	as := ccServer(t)
	store := newRecordingStore()
	opts := cmdOptions(as, store)

	_, stderr, err := runCommand(t, NewLoginCommand(opts...))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if !store.has("set") || !strings.Contains(stderr, "Logged in to "+as.URL) {
		t.Fatalf("login did not store in the configured provider (calls %v), stderr %q", store.calls, stderr)
	}

	stdout, stderr, err := runCommand(t, NewTokenCommand(opts...))
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	if stdout != "cmd-access-token\n" || stderr != "" {
		t.Fatalf("token printed stdout %q stderr %q; want only the token on stdout", stdout, stderr)
	}
	if !store.has("get") {
		t.Fatal("token did not read the configured provider")
	}

	stdout, _, err = runCommand(t, NewTokenCommand(opts...), "--json")
	if err != nil {
		t.Fatal(err)
	}
	var tj map[string]any
	if err := json.Unmarshal([]byte(stdout), &tj); err != nil || tj["access_token"] != "cmd-access-token" || tj["issuer"] != as.URL {
		t.Fatalf("token --json: %s (%v)", stdout, err)
	}
	assertNoSecrets(t, "token --json", stdout, "cmd-client-secret")

	stdout, _, err = runCommand(t, NewStatusCommand(opts...))
	if err != nil || !strings.Contains(stdout, "Logged in to") {
		t.Fatalf("status: %q %v", stdout, err)
	}
	assertNoSecrets(t, "status", stdout, "cmd-access-token", "cmd-client-secret")

	_, stderr, err = runCommand(t, NewLogoutCommand(opts...))
	if err != nil || !strings.Contains(stderr, "Logged out.") || !store.has("delete") {
		t.Fatalf("logout: %q %v calls %v", stderr, err, store.calls)
	}
	if n := len(as.requestsTo("/revoke")); n != 1 {
		t.Fatalf("logout revoked %d tokens, want 1 (access token only; no refresh token)", n)
	}
}

func TestCommandsFailClosed(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	store := storage.NewMemory()
	opts := []Option{WithIssuer(as.URL), WithClientID(testClientID), WithStorage(store), WithHTTPClient(as.Client())}

	if _, _, err := runCommand(t, NewTokenCommand(opts...)); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("token without login: err = %v, want ErrNotLoggedIn", err)
	}
	if _, _, err := runCommand(t, NewStatusCommand(opts...)); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("status without login: err = %v", err)
	}
	_, stderr, err := runCommand(t, NewLogoutCommand(opts...))
	if err != nil || !strings.Contains(stderr, "Not logged in.") {
		t.Fatalf("logout without login: %q %v", stderr, err)
	}
	// A login that fails must make the command fail (non-zero exit).
	as.handle("/device_authorization", func(w http.ResponseWriter, _ *http.Request) { oauthError(w, 400, "unauthorized_client") })
	if _, _, err := runCommand(t, NewLoginCommand(opts...), "--flow", "device"); !errors.Is(err, ErrUnauthorizedClient) {
		t.Fatalf("failed login: err = %v", err)
	}
	if _, _, err := runCommand(t, NewLoginCommand(opts...), "--flow", "password"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("bad --flow: err = %v", err)
	}
}

func TestLoginFlagsReachTheRequest(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	as.handle("/device_authorization", func(w http.ResponseWriter, r *http.Request) {
		writeJSONResponse(w, http.StatusOK, standardDA(as.URL))
	})
	as.handle("/token", func(w http.ResponseWriter, _ *http.Request) { pollOK(w) })
	clock := newFakeClock()
	opts := []Option{
		WithIssuer(as.URL), WithClientID(testClientID), WithStorage(storage.NewMemory()), WithHTTPClient(as.Client()),
		WithClock(clock), WithBrowserOpener(func(context.Context, string) error {
			t.Error("browser opened despite --no-browser")
			return nil
		}),
	}
	_, stderr, err := runCommand(t, NewLoginCommand(opts...), "--flow", "device", "--no-browser", "--scopes", "openid,api:read", "--qr")
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if got := as.requestsTo("/device_authorization")[0].Form.Get("scope"); got != "openid api:read" {
		t.Fatalf("scope = %q", got)
	}
	if !strings.Contains(stderr, "WDJB-MJHT") || !strings.Contains(stderr, "QR code") {
		t.Fatalf("prompt: %s", stderr)
	}
}

func TestNewAuthCommand(t *testing.T) {
	t.Parallel()
	cmd := NewAuthCommand(WithIssuer("https://as.example"), WithClientID("c"))
	var names []string
	for _, c := range cmd.Commands() {
		names = append(names, c.Name())
	}
	if strings.Join(names, ",") != "login,logout,status,token" {
		t.Fatalf("subcommands: %v", names)
	}
}

func TestWriteStatus(t *testing.T) {
	t.Parallel()
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	var b bytes.Buffer
	err := writeStatus(&b, &Status{
		Issuer: "https://as.example", ClientID: "c", Email: "a@example.com", Subject: "u1",
		TokenType: "Bearer", Expiry: now.Add(-3 * time.Minute), Expired: true, HasRefreshToken: true,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"a@example.com (subject u1)", "expired 3m ago", "refreshed on next use", "Refresh token: yes"} {
		if !strings.Contains(b.String(), want) {
			t.Fatalf("status output lacks %q:\n%s", want, b.String())
		}
	}
	for d, want := range map[time.Duration]string{42 * time.Second: "42s", 9 * time.Minute: "9m", 3*time.Hour + 5*time.Minute: "3h5m", 2 * time.Hour: "2h"} {
		if got := humanDuration(d); got != want {
			t.Errorf("humanDuration(%v) = %q, want %q", d, got, want)
		}
	}
}

// The granted scope is server-controlled; status must not echo an escape
// sequence in it to the terminal, whatever the stored record holds.
func TestStatusDoesNotEchoEscapesInScope(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	as.handle("/token", func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(w, 200, map[string]any{
			"access_token": "at", "token_type": "Bearer", "expires_in": 3600,
			"scope": "read \x1b]52;c;ZXZpbA==\a \x1b[2J write",
		})
	})
	store := storage.NewMemory()
	opts := cmdOptions(as, store)
	if _, _, err := runCommand(t, NewLoginCommand(opts...)); err != nil {
		t.Fatalf("login: %v", err)
	}
	// A record written by an older version may hold the raw scope.
	c, err := NewClient(opts...)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := c.StoredToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok.Scope != "read write" {
		t.Fatalf("stored scope %q", tok.Scope)
	}
	tok.Scope = "read \x1b]0;title\a write"
	if err := store.Set(context.Background(), c.StorageKey(), tok); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{nil, {"--json"}} {
		out, _, err := runCommand(t, NewStatusCommand(opts...), args...)
		if err != nil {
			t.Fatalf("status %v: %v", args, err)
		}
		if strings.ContainsAny(out, "\x1b\a") || !strings.Contains(out, "read") {
			t.Fatalf("status %v output: %q", args, out)
		}
	}
}

// NewClientForCommand applies the commands' defaults first, so an app name
// pinned in the shared options wins over the root command's name.
func TestNewClientForCommand(t *testing.T) {
	t.Parallel()
	root := &cobra.Command{Use: "mycli"}
	sub := &cobra.Command{Use: "api"}
	root.AddCommand(sub)
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)

	opts := []Option{WithIssuer("https://as.example"), WithClientID("c")}
	c, err := NewClientForCommand(sub, append(opts, WithAppName("com.example.pinned"))...)
	if err != nil {
		t.Fatal(err)
	}
	if c.cfg.appName != "com.example.pinned" || c.cfg.errOut != &errOut || c.cfg.out != &out {
		t.Fatalf("app name %q, writers %v %v", c.cfg.appName, c.cfg.out, c.cfg.errOut)
	}
	d, err := NewClientForCommand(sub, opts...)
	if err != nil || d.cfg.appName != "mycli" {
		t.Fatalf("default app name: %v %v", d, err)
	}
}

func TestLogoutCommandNoBrowser(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	as.setMetadata("revocation_endpoint", nil)
	as.setMetadata("end_session_endpoint", as.URL+"/logout")
	store := storage.NewMemory()
	opened := false
	opts := []Option{
		WithIssuer(as.URL),
		WithClientID(testClientID),
		WithStorage(store),
		WithHTTPClient(as.Client()),
		WithEndSession(EndSessionOptions{}),
		WithBrowser(true),
		WithBrowserOpener(func(context.Context, string) error { opened = true; return nil }),
	}
	key := storage.Key{Issuer: as.URL, ClientID: testClientID}
	if err := store.Set(context.Background(), key, &storage.Token{AccessToken: "at", TokenType: "Bearer"}); err != nil {
		t.Fatal(err)
	}
	_, stderr, err := runCommand(t, NewLogoutCommand(opts...), "--no-browser")
	if err != nil {
		t.Fatalf("logout --no-browser: %v\n%s", err, stderr)
	}
	if opened {
		t.Fatal("logout --no-browser opened a browser")
	}
	if !strings.Contains(stderr, "To sign out of the provider in your browser too, open:") ||
		!strings.Contains(stderr, as.URL+"/logout?") {
		t.Fatalf("sign-out URL not printed:\n%s", stderr)
	}
}
