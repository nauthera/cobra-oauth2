package auth

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func pollError(status int, code string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) { oauthError(w, status, code) }
}

func pollJSON(status int, v any) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) { writeJSONResponse(w, status, v) }
}

var pollOK = pollJSON(http.StatusOK, map[string]any{
	"access_token": "device-access-token", "token_type": "Bearer", "expires_in": 600, "refresh_token": "device-refresh-token",
})

func standardDA(as string) map[string]any {
	return map[string]any{
		"device_code": "dev-code-secret", "user_code": "WDJB-MJHT",
		"verification_uri": as + "/device", "verification_uri_complete": as + "/device?user_code=WDJB-MJHT",
		"expires_in": 900, "interval": 5,
	}
}

func TestDeviceFlowPollingSemantics(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		polls     []func(http.ResponseWriter)
		wantErr   error
		wantWaits []time.Duration
	}{
		{
			"pending then success",
			[]func(http.ResponseWriter){pollError(400, "authorization_pending"), pollError(400, "authorization_pending"), pollOK},
			nil,
			[]time.Duration{5 * time.Second, 5 * time.Second, 5 * time.Second},
		},
		{
			"slow_down adds 5s permanently",
			[]func(http.ResponseWriter){pollError(400, "slow_down"), pollError(400, "authorization_pending"), pollError(400, "slow_down"), pollOK},
			nil,
			[]time.Duration{5 * time.Second, 10 * time.Second, 10 * time.Second, 15 * time.Second},
		},
		{
			"slow_down with a new interval (GitHub, HTTP 200)",
			[]func(http.ResponseWriter){pollJSON(200, map[string]any{"error": "slow_down", "interval": 12}), pollOK},
			nil,
			[]time.Duration{5 * time.Second, 12 * time.Second},
		},
		{"pending as 428 (Google)", []func(http.ResponseWriter){pollError(http.StatusPreconditionRequired, "authorization_pending"), pollOK}, nil, nil},
		{"pending as 403 (Auth0)", []func(http.ResponseWriter){pollError(http.StatusForbidden, "authorization_pending"), pollOK}, nil, nil},
		{"pending with HTTP 200 (GitHub)", []func(http.ResponseWriter){pollJSON(200, map[string]any{"error": "authorization_pending"}), pollOK}, nil, nil},
		{"access_denied stops", []func(http.ResponseWriter){pollError(400, "authorization_pending"), pollError(400, "access_denied")}, ErrAccessDenied, nil},
		{"expired_token stops", []func(http.ResponseWriter){pollError(400, "expired_token")}, ErrExpiredToken, nil},
		{"unknown provider code is terminal", []func(http.ResponseWriter){pollJSON(200, map[string]any{"error": "device_flow_disabled"})}, ErrUnsupportedFlow, nil},
		{
			// RFC 8628 § 3.5: the server's interval is a floor. nauthera
			// adds 5 s for every slow_down, so it can pass a minute.
			"slow_down past 60s is not capped",
			[]func(http.ResponseWriter){
				pollJSON(400, map[string]any{"error": "slow_down", "interval": 58}),
				pollError(400, "slow_down"),
				pollError(400, "authorization_pending"),
				pollOK,
			},
			nil,
			[]time.Duration{5 * time.Second, 58 * time.Second, 63 * time.Second, 63 * time.Second},
		},
		{
			"5xx after a long interval does not shorten it",
			[]func(http.ResponseWriter){
				pollJSON(400, map[string]any{"error": "slow_down", "interval": 90}),
				func(w http.ResponseWriter) { w.WriteHeader(http.StatusServiceUnavailable) },
				pollOK,
			},
			nil,
			[]time.Duration{5 * time.Second, 90 * time.Second, 90 * time.Second},
		},
		{
			"5xx backs off then succeeds",
			[]func(http.ResponseWriter){func(w http.ResponseWriter) { w.WriteHeader(http.StatusServiceUnavailable) }, pollOK},
			nil,
			[]time.Duration{5 * time.Second, 10 * time.Second},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			as := newFakeAS(t)
			as.handle("/device_authorization", func(w http.ResponseWriter, _ *http.Request) {
				writeJSONResponse(w, http.StatusOK, standardDA(as.URL))
			})
			var mu sync.Mutex
			n := 0
			as.handle("/token", func(w http.ResponseWriter, r *http.Request) {
				if r.PostForm.Get("grant_type") != string(GrantDeviceCode) || r.PostForm.Get("device_code") != "dev-code-secret" {
					t.Errorf("poll form: %v", r.PostForm)
				}
				mu.Lock()
				i := min(n, len(tc.polls)-1)
				n++
				mu.Unlock()
				tc.polls[i](w)
			})
			env := newTestEnv(t, as)
			tok, err := env.client.DeviceLogin(context.Background())
			wantErr := tc.wantErr
			if errors.Is(wantErr, ErrUnsupportedFlow) {
				var oe *OAuthError
				if !errors.As(err, &oe) || oe.Code != "device_flow_disabled" {
					t.Fatalf("err = %v, want the provider's error", err)
				}
				return
			}
			if wantErr != nil {
				if !errors.Is(err, wantErr) {
					t.Fatalf("err = %v, want %v", err, wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("DeviceLogin: %v", err)
			}
			if tok.AccessToken != "device-access-token" || tok.RefreshToken != "device-refresh-token" {
				t.Fatalf("token: %v", tok)
			}
			if tc.wantWaits != nil && !reflect.DeepEqual(env.clock.Waits(), tc.wantWaits) {
				t.Fatalf("waits = %v, want %v", env.clock.Waits(), tc.wantWaits)
			}
			out := env.errOut.String()
			if !strings.Contains(out, "WDJB-MJHT") || !strings.Contains(out, as.URL+"/device") {
				t.Fatalf("prompt lacks the user code or URI:\n%s", out)
			}
			assertNoSecrets(t, "prompt", out+env.out.String(), "dev-code-secret", "device-access-token", "device-refresh-token")
		})
	}
}

func startDevice(t *testing.T, da func(base string) map[string]any, opts ...Option) (*DeviceAuthorization, *testEnv, error) {
	t.Helper()
	as := newFakeAS(t)
	as.handle("/device_authorization", func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(w, http.StatusOK, da(as.URL))
	})
	env := newTestEnv(t, as, opts...)
	got, err := env.client.StartDeviceAuthorization(context.Background())
	return got, env, err
}

func TestDeviceAuthorizationResponseQuirks(t *testing.T) {
	t.Parallel()
	t.Run("verification_url and string numbers (Google, Entra v1)", func(t *testing.T) {
		t.Parallel()
		da, env, err := startDevice(t, func(base string) map[string]any {
			return map[string]any{"device_code": "d", "user_code": "ABCD", "verification_url": base + "/device", "expires_in": "1800", "interval": "7"}
		})
		if err != nil {
			t.Fatal(err)
		}
		if da.VerificationURI == "" || da.VerificationURIComplete != "" || da.Interval != 7*time.Second ||
			!da.ExpiresAt.Equal(env.clock.Now().Add(30*time.Minute)) {
			t.Fatalf("da: %+v", da)
		}
	})
	t.Run("missing interval defaults to 5s", func(t *testing.T) {
		t.Parallel()
		da, _, err := startDevice(t, func(base string) map[string]any {
			return map[string]any{"device_code": "d", "user_code": "ABCD", "verification_uri": base + "/device", "expires_in": 600, "interval": 0}
		})
		if err != nil || da.Interval != 5*time.Second {
			t.Fatalf("interval %v, err %v", da.Interval, err)
		}
	})
	t.Run("an interval above a minute is honored", func(t *testing.T) {
		t.Parallel()
		da, _, err := startDevice(t, func(base string) map[string]any {
			return map[string]any{"device_code": "d", "user_code": "ABCD", "verification_uri": base + "/device", "expires_in": 600, "interval": 120}
		})
		if err != nil || da.Interval != 2*time.Minute {
			t.Fatalf("interval %v, err %v", da.Interval, err)
		}
	})
	t.Run("an interval beyond the code's lifetime is bounded by it", func(t *testing.T) {
		t.Parallel()
		da, _, err := startDevice(t, func(base string) map[string]any {
			return map[string]any{"device_code": "d", "user_code": "ABCD", "verification_uri": base + "/device", "expires_in": 300, "interval": 3600}
		})
		if err != nil || da.Interval != 5*time.Minute {
			t.Fatalf("interval %v, err %v", da.Interval, err)
		}
	})
	t.Run("unsafe verification_uri refused", func(t *testing.T) {
		t.Parallel()
		for _, uri := range []string{"javascript:alert(1)", "file:///etc/passwd", `\\attacker\share\x.exe`, "http://evil.example/device", "https://user@evil.example/"} {
			_, _, err := startDevice(t, func(string) map[string]any {
				return map[string]any{"device_code": "d", "user_code": "ABCD", "verification_uri": uri, "expires_in": 600}
			})
			if err == nil {
				t.Errorf("verification_uri %q accepted", uri)
			}
		}
	})
	t.Run("unsafe verification_uri_complete dropped, never opened", func(t *testing.T) {
		t.Parallel()
		da, _, err := startDevice(t, func(base string) map[string]any {
			return map[string]any{
				"device_code": "d", "user_code": "ABCD", "verification_uri": base + "/device",
				"verification_uri_complete": "ms-msdt:/id PCWDiagnostic", "expires_in": 600,
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		if da.VerificationURIComplete != "" {
			t.Fatalf("unsafe complete URI kept: %q", da.VerificationURIComplete)
		}
	})
	t.Run("user_code with escape sequences refused", func(t *testing.T) {
		t.Parallel()
		_, _, err := startDevice(t, func(base string) map[string]any {
			return map[string]any{"device_code": "d", "user_code": "AB\x1b]8;;https://evil/\x07CD", "verification_uri": base + "/device", "expires_in": 600}
		})
		if !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("missing fields", func(t *testing.T) {
		t.Parallel()
		_, _, err := startDevice(t, func(string) map[string]any { return map[string]any{"user_code": "A"} })
		if !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestDeviceFlowWithoutEndpointDoesNotFallBack(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	as.setMetadata("device_authorization_endpoint", nil)
	env := newTestEnv(t, as, WithClientSecret("s3cret"))
	_, err := env.client.StartDeviceAuthorization(context.Background())
	if !errors.Is(err, ErrUnsupportedFlow) {
		t.Fatalf("err = %v, want ErrUnsupportedFlow", err)
	}
	if n := len(as.requestsTo("/authorize")); n != 0 {
		t.Fatal("credentials were sent to the authorization endpoint")
	}
}

func TestDeviceFlowStopsOnCancel(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	as.handle("/device_authorization", func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(w, http.StatusOK, standardDA(as.URL))
	})
	ctx, cancel := context.WithCancel(context.Background())
	as.handle("/token", func(w http.ResponseWriter, _ *http.Request) {
		cancel()
		oauthError(w, 400, "authorization_pending")
	})
	env := newTestEnv(t, as)
	_, err := env.client.DeviceLogin(ctx)
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrExpiredToken) {
		t.Fatalf("err = %v, want context.Canceled and not ErrExpiredToken", err)
	}
}

func TestDeviceFlowExpires(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	as.handle("/device_authorization", func(w http.ResponseWriter, _ *http.Request) {
		da := standardDA(as.URL)
		da["expires_in"] = 12
		writeJSONResponse(w, http.StatusOK, da)
	})
	as.handle("/token", func(w http.ResponseWriter, _ *http.Request) { oauthError(w, 400, "authorization_pending") })
	env := newTestEnv(t, as)
	_, err := env.client.DeviceLogin(context.Background())
	if !errors.Is(err, ErrExpiredToken) {
		t.Fatalf("err = %v, want ErrExpiredToken", err)
	}
	if n := len(as.requestsTo("/token")); n != 2 {
		t.Fatalf("polled %d times in 12s at a 5s interval, want 2", n)
	}
}

func TestDeviceHandlerAndClientAuth(t *testing.T) {
	t.Parallel()
	as := newFakeAS(t)
	as.handle("/device_authorization", func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(w, http.StatusOK, standardDA(as.URL))
	})
	as.handle("/token", func(w http.ResponseWriter, _ *http.Request) { pollOK(w) })
	var seen *DeviceAuthorization
	env := newTestEnv(t, as, WithDeviceAuthorizationHandler(func(_ context.Context, da *DeviceAuthorization) error {
		seen = da
		return nil
	}), WithScopes("openid", "api:read"), WithAudience("https://api.example"))
	if _, err := env.client.DeviceLogin(context.Background()); err != nil {
		t.Fatal(err)
	}
	if seen == nil || seen.UserCode != "WDJB-MJHT" {
		t.Fatalf("handler got %v", seen)
	}
	if env.errOut.Len() != 0 {
		t.Fatal("the default prompt ran despite a handler")
	}
	assertNoSecrets(t, "DeviceAuthorization.String", seen.String()+seen.GoString(), "dev-code-secret")
	req := as.requestsTo("/device_authorization")[0]
	if req.Form.Get("client_id") != testClientID || req.Form.Get("scope") != "openid api:read" ||
		req.Form.Get("audience") != "https://api.example" || req.Form.Has("client_secret") {
		t.Fatalf("device authorization form: %v", req.Form)
	}
}
