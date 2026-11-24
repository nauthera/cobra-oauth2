package auth_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/nauthera/cobra-oauth2/pkg/auth"
	"github.com/nauthera/cobra-oauth2/pkg/storage"
)

// TestLogoutRemovesUnreadableRecord: a stored token set that cannot be
// read (corrupt, or a file other users can read) cannot be revoked, but
// logout must still delete it instead of leaving it on disk for good.
func TestLogoutRemovesUnreadableRecord(t *testing.T) {
	t.Parallel()
	cases := map[string]func(t *testing.T, path string){
		"corrupt": func(t *testing.T, path string) {
			t.Helper()
			if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"world-readable": func(t *testing.T, path string) {
			t.Helper()
			if runtime.GOOS == "windows" {
				t.Skip("no Unix permission bits on Windows")
			}
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, damage := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			e := plainEnv(t, nil, auth.WithFlow(auth.FlowDevice), auth.WithStorage(storage.NewFile(dir)))
			mustLogin(t, e.client)
			path := filepath.Join(dir, e.client.StorageKey().ID()+".json")
			damage(t, path)

			err := e.client.Logout(t.Context())
			if !errors.Is(err, auth.ErrRevocationFailed) {
				t.Fatalf("Logout = %v, want an error wrapping ErrRevocationFailed", err)
			}
			if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("the unreadable token file is still there: %v", statErr)
			}
			if _, err := e.client.StoredToken(t.Context()); !errors.Is(err, auth.ErrNotLoggedIn) {
				t.Fatalf("StoredToken after logout = %v, want ErrNotLoggedIn", err)
			}
		})
	}
}
