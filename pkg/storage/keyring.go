package storage

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	keyring "github.com/zalando/go-keyring"
)

const (
	// defaultChunkSize keeps every keyring entry below the smallest platform
	// limit go-keyring enforces: 2560 bytes per credential on Windows, and a
	// 4096-byte `security -i` command line on macOS, where the value is
	// base64-encoded (4/3) next to the service and account names.
	defaultChunkSize = 2000
	minChunkSize     = 256
	// maxChunks bounds a read: 64 chunks of 2000 bytes is far more than any
	// token set needs, and a corrupt header cannot make Get loop for long.
	maxChunks    = 64
	chunkHeader  = "chunks:"
	chunkPartSep = "."
)

// keyringBackend is the subset of go-keyring this package uses, so tests can
// substitute a backend with platform-like size limits.
type keyringBackend interface {
	Set(service, user, password string) error
	Get(service, user string) (string, error)
	Delete(service, user string) error
}

type systemKeyring struct{}

func (systemKeyring) Set(service, user, password string) error {
	return keyring.Set(service, user, password)
}

func (systemKeyring) Get(service, user string) (string, error) {
	return keyring.Get(service, user)
}

func (systemKeyring) Delete(service, user string) error {
	return keyring.Delete(service, user)
}

type keyringProvider struct {
	service   string
	backend   keyringBackend
	chunkSize int
	lockDir   string // "" means <user cache dir>/<service>/locks
	mu        sync.Mutex
}

// KeyringOption configures [NewKeyring].
type KeyringOption func(*keyringProvider)

// WithChunkSize sets the largest value written to a single keyring entry.
// Larger token sets are split across several entries. The default suits
// every platform go-keyring supports; lower it only if your keyring
// rejects writes with go-keyring's ErrSetDataTooBig.
func WithChunkSize(n int) KeyringOption {
	return func(k *keyringProvider) {
		if n >= minChunkSize {
			k.chunkSize = n
		}
	}
}

// WithLockDir sets the directory of the lock files that keep two processes
// from refreshing the same token set at once (see [Locker]). The default is
// <user cache dir>/<service>/locks.
func WithLockDir(dir string) KeyringOption {
	return func(k *keyringProvider) { k.lockDir = dir }
}

// NewKeyring returns a Provider backed by the operating system's credential
// store (macOS Keychain, Windows Credential Manager, the Secret Service on
// Linux) through github.com/zalando/go-keyring.
//
// service names the application in the keyring and should be unique to it,
// for example a reverse-DNS name such as "com.example.mycli". Each token set
// is stored under an account name derived from its [Key], and records too
// large for one entry are split across several. The provider implements
// [Locker] with lock files under the user's cache directory.
func NewKeyring(service string, opts ...KeyringOption) Provider {
	k := &keyringProvider{service: service, backend: systemKeyring{}, chunkSize: defaultChunkSize}
	for _, opt := range opts {
		opt(k)
	}
	return k
}

func (k *keyringProvider) validate(key Key) error {
	if k.service == "" {
		return errors.New("keyring storage: service name is required")
	}
	return key.Validate()
}

func partAccount(head string, i int) string {
	return head + chunkPartSep + strconv.Itoa(i)
}

// chunkCount parses a chunk header, returning 0 for a plain record.
func chunkCount(head string) (int, error) {
	rest, ok := strings.CutPrefix(head, chunkHeader)
	if !ok {
		return 0, nil
	}
	n, err := strconv.Atoi(rest)
	if err != nil || n < 1 || n > maxChunks {
		return 0, fmt.Errorf("%w: invalid chunk header", ErrCorrupt)
	}
	return n, nil
}

// Get implements Provider.
func (k *keyringProvider) Get(_ context.Context, key Key) (*Token, error) {
	if err := k.validate(key); err != nil {
		return nil, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()

	account := key.ID()
	head, err := k.backend.Get(k.service, account)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("read keyring: %w", err)
	}
	n, err := chunkCount(head)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return decodeRecord(key, []byte(head))
	}
	var b strings.Builder
	for i := 1; i <= n; i++ {
		part, err := k.backend.Get(k.service, partAccount(account, i))
		if err != nil {
			if errors.Is(err, keyring.ErrNotFound) {
				return nil, fmt.Errorf("%w: chunk %d of %d is missing", ErrCorrupt, i, n)
			}
			return nil, fmt.Errorf("read keyring: %w", err)
		}
		b.WriteString(part)
	}
	return decodeRecord(key, []byte(b.String()))
}

// Set implements Provider.
func (k *keyringProvider) Set(_ context.Context, key Key, token *Token) error {
	if err := k.validate(key); err != nil {
		return err
	}
	data, err := encodeRecord(key, token)
	if err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()

	account := key.ID()
	oldParts := k.existingParts(account)

	size := k.chunkSize
	for {
		parts, err := k.write(account, string(data), size)
		if err == nil {
			k.deleteParts(account, parts+1, oldParts)
			return nil
		}
		if !errors.Is(err, keyring.ErrSetDataTooBig) || size/2 < minChunkSize {
			return fmt.Errorf("write keyring: %w", err)
		}
		size /= 2
	}
}

// write stores value under account, split into chunks of at most size bytes
// when needed, and returns the number of chunk entries written. Chunks are
// written before the header, so a reader never sees a header that points at
// chunks that do not exist yet.
func (k *keyringProvider) write(account, value string, size int) (int, error) {
	if len(value) <= size {
		return 0, k.backend.Set(k.service, account, value)
	}
	parts := splitUTF8(value, size)
	if len(parts) > maxChunks {
		return 0, fmt.Errorf("token record of %d bytes is too large for the keyring: %w", len(value), keyring.ErrSetDataTooBig)
	}
	for i, p := range parts {
		if err := k.backend.Set(k.service, partAccount(account, i+1), p); err != nil {
			return 0, err
		}
	}
	return len(parts), k.backend.Set(k.service, account, chunkHeader+strconv.Itoa(len(parts)))
}

// existingParts returns how many chunk entries the current record has.
func (k *keyringProvider) existingParts(account string) int {
	head, err := k.backend.Get(k.service, account)
	if err != nil {
		return 0
	}
	n, err := chunkCount(head)
	if err != nil {
		return maxChunks // corrupt header: clean up everything we might own
	}
	return n
}

func (k *keyringProvider) deleteParts(account string, from, to int) {
	for i := from; i <= to; i++ {
		_ = k.backend.Delete(k.service, partAccount(account, i))
	}
}

// Delete implements Provider.
func (k *keyringProvider) Delete(_ context.Context, key Key) error {
	if err := k.validate(key); err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()

	account := key.ID()
	k.deleteParts(account, 1, k.existingParts(account))
	if err := k.backend.Delete(k.service, account); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return fmt.Errorf("delete keyring entry: %w", err)
	}
	return nil
}

// splitUTF8 splits s into pieces of at most size bytes without cutting a
// UTF-8 sequence in half (the Secret Service requires valid UTF-8 strings).
func splitUTF8(s string, size int) []string {
	var parts []string
	for len(s) > size {
		cut := size
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		if cut == 0 {
			cut = size
		}
		parts = append(parts, s[:cut])
		s = s[cut:]
	}
	if s != "" {
		parts = append(parts, s)
	}
	return parts
}
