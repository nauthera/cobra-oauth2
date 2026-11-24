# Go testing conventions

Enforced in review (and, where noted, by `just lint`). Applies to every `*_test.go` file.

## Every test is parallel and self-contained

- `t.Parallel()` is the first statement of every top-level test, and of every table row
  that builds its own state. A row that drives the parent's state in sequence does not.
- A test stays serial only when it touches process-wide state, and says why in its first
  line (`// Not parallel: it changes the environment.`): `t.Setenv` (`TestHeadless`),
  `keyring.MockInit()` (`TestSystemKeyringMock`), a package-level variable. A new seam is
  an option or a field, never a package variable a test swaps.
- The context is `t.Context()`, files live under `t.TempDir()` (usetesting enforces both),
  a server is `httptest` or `oauthtest.New`, a listener `127.0.0.1:0`. Never a fixed port.
- **No real network, browser or keyring.** The client gets `WithHTTPClient(srv.Client())`
  and `WithBrowser(false)`, or `WithBrowserOpener(as.OpenBrowser)` to drive the browser
  flow; tokens go to `storage.NewMemory()`. Keyring code is tested through a fake
  `keyringBackend` (`newTestKeyring`) or go-keyring's mock, never the OS keyring.
- **No `time.Sleep` to wait for time to pass.** Inject a fake clock (`WithClock`): its
  `After` fires at once and records the wait, so polling, backoff and expiry run instantly
  and `Waits()` shows what the client waited. Wait for a goroutine on a channel in a
  `select` with a deadline.
- The suite runs with `-race` in `just check` and CI; a test with goroutines must pass it.

## Which helper

Look here before writing one. `pkg/auth` has two test packages: white-box tests
(`package auth`) and black-box tests (`package auth_test`), which see only the public API.

| You need | Use | Where |
| --- | --- | --- |
| A full authorization server: discovery, PKCE, PAR, device, refresh rotation, DPoP, revocation, introspection, ID tokens | `oauthtest.New(t, oauthtest.Config{...})`; drive it with `ApproveDevice`, `DenyDevice`, `Config.DeviceScript`, `SetMetadata`, `Override`, inspect it with `Requests`, `Revoked` | `internal/oauthtest` |
| A provider deviation at that server | a field of `oauthtest.Quirks` (`ErrorStatus`, `FormEncoded`, `StringNumbers`, `VerificationURL`, `TokenType`, …) | `internal/oauthtest` |
| A response captured from a real server | `as.Override(kind, as.Replay(path))` over a `RecordedResponse` fixture; `oauthtest.LoadJSON` for a discovery document | `internal/oauthtest` |
| A clock shared by client and server | `oauthtest.NewClock(oauthtest.DefaultStart)`, with `Config.Now = clock.Now` | `internal/oauthtest` |
| A black-box client on that server | `newEnv`, `plainEnv`, `newNauthera`, `nautheraCLIEnv`, `newCLI`; `e.newClient` for a second run; `mustLogin`, `wantErr`, `oauthErr`, `assertNoSecret` | `env_test.go`, `options_test.go`, `nauthera_test.go`, `commands_test.go` |
| A white-box test of one endpoint shape | `newFakeAS(t)` (one handler per path, `requestsTo`, `setMetadata`, `idToken`), `newTestEnv(t, as, opts...)`, `newFakeClock`, `signJWT`, `writeJSONResponse`, `oauthError`, `assertNoSecrets` | `pkg/auth/helpers_test.go` |
| A flow's own white-box stack | `newBrowserAS`, `newDPoPAS`, `rotatingServer`, `startDevice`, `transportEnv`, `loopbackClient`, `runCommand` | the flow's `_test.go` |
| A storage provider's behaviour | `providerContract(t, p)`, which every `storage.Provider` passes; `sampleToken`, `assertMode` | `pkg/storage/storage_test.go` |

Prefer `oauthtest` for a new test of a flow or of provider behaviour; it is strict enough to
catch a client that cuts corners. Use `newFakeAS` only for a shape `oauthtest` does not
produce, and if a second test needs that shape, make it a `Config` or `Quirks` field
instead of a second handler.

## Fixtures

- `pkg/auth/testdata/nauthera/` holds nauthera-server's discovery documents and recorded
  responses; its `README.md` lists each file and how to refresh it.
- `pkg/auth/testdata/providers/<provider>/` holds other providers' documents, read through
  `providerFixture` in `providers_test.go`.
- Fixtures use the `{{issuer}}`, `{{base}}` and `{{origin}}` placeholders, and every token,
  code, nonce and secret in them is redacted. A test relies on the shape (status, `error`
  code, headers, members), never on an `error_description` text.

## Fuzz targets

Every parser of server- or browser-controlled input has a fuzz target in
`pkg/auth/fuzz_test.go` (`FuzzDecodeTokenResponse`, `FuzzDiscoveryDocument`, `FuzzCallback`,
…). A new parser gets one: seeds with `f.Add`, and a body that checks no panic, no unsafe
rune in what can be printed (`assertPrintable`) and no secret in an error. Plain `go test`
replays the seeds and `pkg/auth/testdata/fuzz/`; `go test -fuzz=FuzzX ./pkg/auth` explores,
and a crasher it finds is committed under `testdata/fuzz/FuzzX/`.

## Live tests

`e2e/` runs against a real nauthera-server behind `//go:build e2e`, and skips unless the
`NAUTHERA_E2E_*` variables are set (`e2e/README.md`). `just test` never runs it and
`just vet` vets it. It covers what only a real server shows; a property a fixture can pin
belongs in the unit suite.

## Writing a helper

- Search first (`code-economy.md` § 1). A helper only one file uses stays in that file; one
  every black-box or every white-box test needs goes in `env_test.go` or
  `helpers_test.go`; server behaviour goes in `internal/oauthtest`.
- It takes `t` first (`testing.TB` when a fuzz target may call it), calls `t.Helper()`,
  fails through `t.Fatalf`, returns values rather than an error, and cleans up with
  `t.Cleanup`.

## Assertions: standard library only

- No testify or any other assertion module (the module adds no test dependency to what
  importers resolve). Check with `if` and fail with `t.Fatalf`, naming the operation, what
  came back, and what was wanted: `t.Fatalf("Get on empty store: err = %v, want ErrNotFound", err)`.
- `t.Fatalf` when a later line would panic or mean nothing; `t.Errorf` for independent
  checks reported from one run.
- Errors are checked with `errors.Is` against the sentinel (`ErrLoginRequired`,
  `ErrInvalidConfig`) or `errors.As` into `*auth.OAuthError`, not by comparing messages.
- A flow that touches a secret asserts it never reached the output or an error
  (`assertNoSecrets`, `assertNoSecret`).

## Proportion

- One property, one tier: a rule is a table of cases in the file of the code that owns it;
  a flow test asserts what the flow adds, not the rule again.
- The name states the property (`TestDeviceFlowStopsOnCancel`), scenarios go in `t.Run`
  rows (`TestDeviceFlowPollingSemantics`), and a comment above a test is at most a spec citation or the attack it
  pins, never the name again.
