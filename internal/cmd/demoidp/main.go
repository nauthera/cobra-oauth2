// Command demoidp runs the fake authorization server from
// internal/oauthtest on a loopback port, configured like nauthera-server,
// for recording demo.gif (see demo.tape and scripts/demo-setup.sh).
//
// Run it from the repository root, where it reads nauthera's discovery
// fixture. It prints the issuer and the client ID as shell assignments, then
// serves until interrupted. Every device authorization is approved on the third
// poll, so a recording needs no browser.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/nauthera/cobra-oauth2/internal/oauthtest"
)

const clientID = "demo-cli"

func main() {
	tb := &shim{}
	srv := oauthtest.New(tb, oauthtest.Config{
		// nauthera-server's discovery document: DPoP with server nonces,
		// PAR, revocation, end-session.
		Metadata: oauthtest.LoadJSON(tb, "pkg/auth/testdata/nauthera/discovery.json"),
		Clients: []oauthtest.Client{{
			ID:           clientID,
			RedirectURIs: []string{"http://127.0.0.1/callback"},
		}},
		AccessTokenTTL: time.Hour,
		RefreshScope:   "offline_access",
		DPoP:           oauthtest.DPoPPolicy{Enabled: true, RequireNonce: true},
		DeviceScript:   []oauthtest.DeviceStep{oauthtest.DevicePending, oauthtest.DevicePending, oauthtest.DeviceApprove},
		DeviceInterval: 1,
		UserCode:       "WDJB-MJHT",
		Subject:        "c0a8f1e2-ada",
		IDTokenClaims:  map[string]any{"email": "ada@example.com", "name": "Ada Lovelace"},
	})
	fmt.Fprintf(os.Stdout, "export NAUTHERA_ISSUER=%s NAUTHERA_CLIENT_ID=%s\n", srv.URL, clientID)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	tb.cleanup()
}

// shim satisfies the parts of testing.TB that oauthtest.New uses outside a
// test. Calling any other method panics, which is fine for a demo.
type shim struct {
	testing.TB
	cleanups []func()
}

func (*shim) Helper() {}

func (s *shim) Cleanup(f func()) { s.cleanups = append(s.cleanups, f) }

func (*shim) Errorf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "demoidp: "+format+"\n", args...)
}

func (*shim) Fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "demoidp: "+format+"\n", args...)
	os.Exit(1)
}

func (s *shim) cleanup() {
	for i := len(s.cleanups) - 1; i >= 0; i-- {
		s.cleanups[i]()
	}
}
