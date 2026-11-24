package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestFileLockerExcludes(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" && runtime.GOOS != "windows" &&
		runtime.GOOS != "freebsd" && runtime.GOOS != "openbsd" && runtime.GOOS != "netbsd" {
		t.Skip("no file locking on " + runtime.GOOS)
	}
	dir := filepath.Join(t.TempDir(), "locks")
	l := NewFileLocker(dir)
	unlock, err := l.Lock(context.Background(), testKey)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(dir); err != nil || (runtime.GOOS != "windows" && info.Mode().Perm() != lockDirPerm) {
		t.Fatalf("lock directory: %v %v", info, err)
	}

	// A second holder, as another process would be, waits.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := NewFileLocker(dir).Lock(ctx, testKey); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second Lock while held: %v", err)
	}
	// Another key is independent.
	other, err := l.Lock(context.Background(), Key{Issuer: testKey.Issuer, ClientID: "other"})
	if err != nil {
		t.Fatalf("another key: %v", err)
	}
	other()

	got := make(chan error, 1)
	go func() {
		u, err := NewFileLocker(dir).Lock(context.Background(), testKey)
		if err == nil {
			u()
		}
		got <- err
	}()
	time.Sleep(20 * time.Millisecond)
	unlock()
	unlock() // idempotent
	select {
	case err := <-got:
		if err != nil {
			t.Fatalf("Lock after release: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the lock was not handed over after release")
	}
}

func TestLockerErrors(t *testing.T) {
	t.Parallel()
	if _, err := NewFileLocker(t.TempDir()).Lock(context.Background(), Key{}); err == nil {
		t.Fatal("an invalid key was locked")
	}
	// A directory that cannot be created is an error for an explicit file
	// locker, and no locking for the keyring.
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileLocker(filepath.Join(file, "locks")).Lock(context.Background(), testKey); err == nil {
		t.Fatal("lock under a regular file succeeded")
	}
	k := NewKeyring("svc", WithLockDir(filepath.Join(file, "locks"))).(Locker)
	unlock, err := k.Lock(context.Background(), testKey)
	if err != nil {
		t.Fatalf("keyring lock must degrade, not fail: %v", err)
	}
	unlock()
	if _, err := NewKeyring("").(Locker).Lock(context.Background(), testKey); err == nil {
		t.Fatal("keyring without a service locked")
	}
	if unlock, err := NewFileLocker("").Lock(context.Background(), testKey); err != nil {
		t.Fatalf("empty dir: %v", err)
	} else {
		unlock()
	}
	// A lock file that cannot be opened (here a directory in its place)
	// is an error for the file locker, which must not report a lock it
	// does not hold, and no locking for the keyring.
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, testKey.ID()+".lock"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileLocker(dir).Lock(context.Background(), testKey); err == nil {
		t.Fatal("lock succeeded although the lock file cannot be opened")
	}
	unlock, err = NewKeyring("svc", WithLockDir(dir)).(Locker).Lock(context.Background(), testKey)
	if err != nil {
		t.Fatalf("keyring lock must degrade, not fail: %v", err)
	}
	unlock()
}

func TestProvidersAreLockers(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for name, p := range map[string]Provider{
		"file":     NewFile(dir),
		"keyring":  NewKeyring("svc", WithLockDir(t.TempDir())),
		"fallback": Fallback(NewMemory(), NewFile(dir)),
		"memory":   Fallback(NewMemory(), NewMemory()),
	} {
		l, ok := p.(Locker)
		if !ok {
			t.Fatalf("%s is not a Locker", name)
		}
		unlock, err := l.Lock(context.Background(), testKey)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		unlock()
	}
	if _, ok := NewMemory().(Locker); ok {
		t.Fatal("memory storage is process-local and needs no lock")
	}
	if _, err := Fallback(NewMemory(), NewMemory()).(Locker).Lock(context.Background(), Key{}); err == nil {
		t.Fatal("fallback locked an invalid key")
	}
}

func TestLockDirName(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"com.example.mycli": "com.example.mycli",
		"my cli/../x":       "my_cli_.._x",
		"..":                "cobra-oauth2",
		"":                  "cobra-oauth2",
	} {
		if got := lockDirName(in); got != want {
			t.Errorf("lockDirName(%q) = %q, want %q", in, got, want)
		}
	}
	if d := defaultLockDir("svc"); d != "" && filepath.Base(filepath.Dir(d)) != "svc" {
		t.Errorf("defaultLockDir = %q", d)
	}
}
