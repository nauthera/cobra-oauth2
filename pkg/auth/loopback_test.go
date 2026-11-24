package auth

import (
	"net"
	"strconv"
	"testing"

	"github.com/nauthera/cobra-oauth2/pkg/storage"
)

func loopbackClient(t *testing.T, opts ...Option) *Client {
	t.Helper()
	all := append([]Option{
		WithIssuer("https://as.example"), WithClientID("c"), WithStorage(storage.NewMemory()),
	}, opts...)
	c, err := NewClient(all...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestListenLocalhostBindsBothLoopbacks: for "localhost" the browser may
// connect to ::1 instead of 127.0.0.1, so the redirect listener must hold
// the port on both, or another local process could take the other one and
// receive the authorization response.
func TestListenLocalhostBindsBothLoopbacks(t *testing.T) {
	t.Parallel()
	if !ipv6LoopbackAvailable(t.Context()) {
		t.Skip("no IPv6 loopback on this machine")
	}
	c := loopbackClient(t, WithRedirectHost("LocalHost"))
	lns, port, err := c.listenLoopback(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, ln := range lns {
			_ = ln.Close()
		}
	})
	if len(lns) != 2 {
		t.Fatalf("got %d listeners, want 127.0.0.1 and ::1", len(lns))
	}
	for _, ln := range lns {
		addr, ok := ln.Addr().(*net.TCPAddr)
		if !ok || addr.Port != port || !addr.IP.IsLoopback() {
			t.Fatalf("listener on %s, want loopback port %d", ln.Addr(), port)
		}
	}
	for _, host := range []string{"127.0.0.1", "::1"} {
		var lc net.ListenConfig
		if ln, err := lc.Listen(t.Context(), "tcp", net.JoinHostPort(host, strconv.Itoa(port))); err == nil {
			_ = ln.Close()
			t.Fatalf("%s:%d is still free for another process", host, port)
		}
	}
}

// TestListenLocalhostRefusesSquattedIPv6Port: a fixed port that someone
// else holds on ::1 is an error, not a login whose redirect may go to them.
func TestListenLocalhostRefusesSquattedIPv6Port(t *testing.T) {
	t.Parallel()
	if !ipv6LoopbackAvailable(t.Context()) {
		t.Skip("no IPv6 loopback on this machine")
	}
	var lc net.ListenConfig
	squatter, err := lc.Listen(t.Context(), "tcp", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = squatter.Close() })
	port := squatter.Addr().(*net.TCPAddr).Port //nolint:forcetypeassert // a TCP listener

	c := loopbackClient(t, WithRedirectHost("localhost"), WithRedirectPort(port))
	lns, _, err := c.listenLoopback(t.Context())
	if err == nil {
		for _, ln := range lns {
			_ = ln.Close()
		}
		t.Fatal("listened although another process holds the port on ::1")
	}
	// The IPv4 half must not stay bound after the failure.
	ln, err := lc.Listen(t.Context(), "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("127.0.0.1:%d left bound: %v", port, err)
	}
	_ = ln.Close()
}

func TestListenLoopbackSingleHost(t *testing.T) {
	t.Parallel()
	for _, host := range []string{"127.0.0.1", "[::1]"} {
		if host == "[::1]" && !ipv6LoopbackAvailable(t.Context()) {
			continue
		}
		c := loopbackClient(t, WithRedirectHost(host))
		lns, port, err := c.listenLoopback(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if len(lns) != 1 || port == 0 {
			t.Fatalf("%s: %d listeners on port %d", host, len(lns), port)
		}
		_ = lns[0].Close()
	}
}
