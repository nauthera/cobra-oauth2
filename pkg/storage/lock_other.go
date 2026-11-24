//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd || windows)

package storage

import "os"

// tryLockFile does not lock on platforms without flock or LockFileEx; the
// in-process lock of the auth package still applies.
func tryLockFile(*os.File) (bool, error) { return true, nil }

func unlockFile(*os.File) error { return nil }
