package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
)

const (
	fileDirPerm  fs.FileMode = 0o700
	fileFilePerm fs.FileMode = 0o600
	// maxFileSize bounds how much a token file read may allocate.
	maxFileSize = 1 << 20
)

type fileProvider struct {
	dir string
	mu  sync.Mutex
}

// DefaultFileDir returns the directory [NewFile] should use for an
// application: <user config dir>/<app>/tokens, for example
// ~/.config/mycli/tokens on Linux.
func DefaultFileDir(app string) (string, error) {
	if app == "" || app != filepath.Base(app) || app == "." || app == ".." {
		return "", fmt.Errorf("default token directory: invalid application name %q", app)
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("default token directory: %w", err)
	}
	return filepath.Join(base, app, "tokens"), nil
}

// NewFile returns a Provider that writes one JSON file per token set into
// dir, creating dir with mode 0700 when needed. Files are written atomically
// (a temporary file renamed into place) with mode 0600, and on Unix a file
// that other users can read or write is refused with
// [ErrInsecurePermissions].
//
// The provider implements [Locker] with a lock file per token set in dir.
//
// Tokens in a file are protected only by file permissions. Prefer
// [NewKeyring], and use this provider where no keyring exists (containers,
// headless CI) or as the secondary of [Fallback].
func NewFile(dir string) Provider {
	return &fileProvider{dir: dir}
}

func (f *fileProvider) path(key Key) string {
	return filepath.Join(f.dir, key.ID()+".json")
}

// Get implements Provider.
func (f *fileProvider) Get(_ context.Context, key Key) (*Token, error) {
	if err := key.Validate(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	p := f.path(key)
	file, err := os.Open(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Windows reports a path below a regular file as not found where
			// Unix says "not a directory"; a misconfigured directory is an
			// error on every platform, not an empty store.
			if info, statErr := os.Stat(f.dir); statErr == nil && !info.IsDir() {
				return nil, fmt.Errorf("token directory %s: not a directory", f.dir)
			}
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("open token file: %w", err)
	}
	defer func() { _ = file.Close() }()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat token file: %w", err)
	}
	if err := checkPerm(info); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read token file: %w", err)
	}
	if len(data) > maxFileSize {
		return nil, fmt.Errorf("%w: file too large", ErrCorrupt)
	}
	return decodeRecord(key, data)
}

func checkPerm(info fs.FileInfo) error {
	if runtime.GOOS == "windows" {
		// Windows has no Unix permission bits; the file inherits the ACL of
		// the user's profile directory.
		return nil
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: mode %#o, want 0600", ErrInsecurePermissions, info.Mode().Perm())
	}
	return nil
}

// Set implements Provider.
func (f *fileProvider) Set(_ context.Context, key Key, token *Token) error {
	if err := key.Validate(); err != nil {
		return err
	}
	data, err := encodeRecord(key, token)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	if err := os.MkdirAll(f.dir, fileDirPerm); err != nil {
		return fmt.Errorf("create token directory: %w", err)
	}
	tmp, err := os.CreateTemp(f.dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("create token file: %w", err)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	// CreateTemp already uses 0600; Chmod makes it explicit and independent
	// of the umask.
	if err := tmp.Chmod(fileFilePerm); err != nil && runtime.GOOS != "windows" {
		return fmt.Errorf("chmod token file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("write token file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync token file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close token file: %w", err)
	}
	if err := os.Rename(tmpName, f.path(key)); err != nil {
		return fmt.Errorf("replace token file: %w", err)
	}
	committed = true
	return nil
}

// Delete implements Provider.
func (f *fileProvider) Delete(_ context.Context, key Key) error {
	if err := key.Validate(); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := os.Remove(f.path(key)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("delete token file: %w", err)
	}
	return nil
}
