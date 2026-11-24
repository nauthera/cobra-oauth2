package storage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Locker is implemented by providers whose token sets are shared between
// processes, such as the keyring or a token directory. The auth package
// holds the lock across reading, refreshing and storing a token set, so
// that two runs of a CLI at the same moment do not both redeem the same
// refresh token. Servers that rotate refresh tokens treat the second
// redemption as theft and revoke the whole grant.
//
// A custom [Provider] backed by shared storage should implement Locker as
// well, for example with [NewFileLocker] or a lock in its own backend.
type Locker interface {
	// Lock blocks until the caller holds an exclusive lock for key, shared
	// with other processes on the machine, or until ctx is done. The
	// returned function releases the lock; calling it more than once is
	// safe.
	Lock(ctx context.Context, key Key) (unlock func(), err error)
}

const (
	// maxLockWait bounds how long Lock waits for another process. A refresh
	// takes one HTTP request, so a lock held longer than this belongs to a
	// process that is stuck.
	maxLockWait  = time.Minute
	lockDirPerm  = 0o700
	lockFilePerm = 0o600
)

type fileLocker struct {
	dir string
	// bestEffort turns a lock directory that cannot be created into no
	// locking at all, for the keyring, whose tokens do not live there.
	bestEffort bool
}

// NewFileLocker returns a Locker that takes an advisory lock on a file per
// key in dir (flock on Unix, LockFileEx on Windows), creating dir with mode
// 0700 when needed. The lock is released when the process exits, so a
// crashed process cannot leave a stale lock behind. On platforms without
// file locking it only validates the key.
func NewFileLocker(dir string) Locker {
	return &fileLocker{dir: dir}
}

// defaultLockDir returns <user cache dir>/<service>/locks, or "" when there
// is no cache directory.
func defaultLockDir(service string) string {
	base, err := os.UserCacheDir()
	if err != nil || base == "" {
		return ""
	}
	return filepath.Join(base, lockDirName(service), "locks")
}

// lockDirName turns a keyring service name into one safe path element.
func lockDirName(service string) string {
	name := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		}
		return '_'
	}, service)
	if strings.Trim(name, ".") == "" {
		return "cobra-oauth2"
	}
	return name
}

// Lock implements Locker.
func (l *fileLocker) Lock(ctx context.Context, key Key) (func(), error) {
	if err := key.Validate(); err != nil {
		return nil, err
	}
	noop := func() {}
	if l.dir == "" {
		return noop, nil
	}
	if err := os.MkdirAll(l.dir, lockDirPerm); err != nil {
		if l.bestEffort {
			return noop, nil
		}
		return nil, fmt.Errorf("create lock directory: %w", err)
	}
	path := filepath.Join(l.dir, key.ID()+".lock")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, lockFilePerm)
	if err != nil {
		if l.bestEffort {
			return noop, nil
		}
		return nil, fmt.Errorf("open lock file: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, maxLockWait)
	defer cancel()
	delay := 5 * time.Millisecond
	for {
		ok, err := tryLockFile(f)
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("lock %s: %w", path, err)
		}
		if ok {
			var once sync.Once
			return func() {
				once.Do(func() {
					_ = unlockFile(f)
					_ = f.Close()
				})
			}, nil
		}
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			_ = f.Close()
			return nil, fmt.Errorf("wait for the lock on %s held by another process: %w", path, ctx.Err())
		case <-t.C:
		}
		delay = min(delay*2, 100*time.Millisecond)
	}
}

// Lock implements Locker with a lock file in the token directory.
func (f *fileProvider) Lock(ctx context.Context, key Key) (func(), error) {
	return (&fileLocker{dir: f.dir}).Lock(ctx, key)
}

// Lock implements Locker with a lock file under the user's cache
// directory, <cache dir>/<service>/locks. The keyring has no locking of its
// own; when the cache directory is unavailable, locking is skipped.
func (k *keyringProvider) Lock(ctx context.Context, key Key) (func(), error) {
	if err := k.validate(key); err != nil {
		return nil, err
	}
	dir := k.lockDir
	if dir == "" {
		dir = defaultLockDir(k.service)
	}
	return (&fileLocker{dir: dir, bestEffort: true}).Lock(ctx, key)
}

// Lock implements Locker: it locks with primary if primary is a Locker,
// otherwise with secondary, otherwise not at all.
func (p *fallbackProvider) Lock(ctx context.Context, key Key) (func(), error) {
	for _, s := range []Provider{p.primary, p.secondary} {
		if l, ok := s.(Locker); ok {
			return l.Lock(ctx, key)
		}
	}
	if err := key.Validate(); err != nil {
		return nil, err
	}
	return func() {}, nil
}
