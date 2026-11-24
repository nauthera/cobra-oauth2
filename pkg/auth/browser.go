package auth

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"runtime"
	"sync"

	"github.com/pkg/browser"
)

var quietBrowser sync.Once

// openSystemBrowser is the default BrowserOpener. pkg/browser runs the
// platform's opener (open, xdg-open, rundll32) with its output wired to the
// package-level browser.Stdout and browser.Stderr, which default to the
// process's own; they are pointed at io.Discard once so a chatty xdg-open
// cannot corrupt the output of a command such as `mycli token`.
func openSystemBrowser(_ context.Context, u string) error {
	quietBrowser.Do(func() {
		browser.Stdout = io.Discard
		browser.Stderr = io.Discard
	})
	return browser.OpenURL(u)
}

// headless reports whether this session probably cannot show a browser to
// the user: an SSH session, or a Unix desktop-less session.
func headless() bool {
	for _, v := range []string{"SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY"} {
		if os.Getenv(v) != "" {
			return true
		}
	}
	switch runtime.GOOS {
	case "windows", "darwin", "ios", "android":
		return false
	default:
		return os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == ""
	}
}

// browserUsable reports whether the client should try to open a browser.
func (c *Client) browserUsable() bool {
	switch c.cfg.browser {
	case browserOn:
		return true
	case browserOff:
		return false
	default:
		return !headless()
	}
}

// safeBrowserURL parses a URL received from the server and returns its
// normalized form if it is safe to open or print: https (http only for a
// loopback host or with WithInsecureHTTP), with a host and without userinfo.
// Anything else (file:, javascript:, UNC paths, custom protocol handlers)
// is refused, because the platform opener would hand it to whatever program
// is registered for it.
func (c *Client) safeBrowserURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: unparsable URL", ErrInvalidResponse)
	}
	if u.User != nil || u.Hostname() == "" || u.Opaque != "" {
		return nil, fmt.Errorf("%w: URL %q is not an absolute web URL", ErrInvalidResponse, sanitize(raw, maxURILen))
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !c.cfg.insecureHTTP && !isLoopbackBrowserHost(u.Hostname()) {
			return nil, fmt.Errorf("%w: refusing plain-http URL %s", ErrInsecureEndpoint, u.Redacted())
		}
	default:
		return nil, fmt.Errorf("%w: refusing URL with scheme %q", ErrInvalidResponse, sanitize(u.Scheme, 16))
	}
	return u, nil
}

// tryOpenBrowser opens u when the configuration allows it and reports
// whether it did. A failure is not an error: the URL is printed anyway.
func (c *Client) tryOpenBrowser(ctx context.Context, u string) bool {
	if !c.browserUsable() {
		return false
	}
	open := c.cfg.openBrowser
	if open == nil {
		open = openSystemBrowser
	}
	if err := open(ctx, u); err != nil {
		c.logger().DebugContext(ctx, "could not open browser", "error", err)
		return false
	}
	return true
}
