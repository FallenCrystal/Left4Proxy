// Package security contains the authenticated wire-session primitives used by
// Left4Proxy.  It deliberately has no dependency on the configuration or
// client/server packages so every transport path can share the same checks.
package security

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const KeySize = 32

var (
	ErrSecretMissing    = errors.New("shared .secret file is missing")
	ErrSecretFormat     = errors.New("shared .secret must contain exactly 32 random bytes encoded as hexadecimal")
	ErrSecretPermission = errors.New("shared .secret is readable by group or other users")
	ErrSecretSymlink    = errors.New("shared .secret must not be a symbolic link")
)

// LoadSecret reads a shared 256-bit key from path.  The file format is 64
// hexadecimal characters with optional surrounding whitespace.  When create
// is true, a missing file is generated atomically with owner-only permissions;
// an existing file is always validated rather than silently replaced.
func LoadSecret(path string, create bool) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("secret path is empty")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve secret path: %w", err)
	}

	data, readErr := os.ReadFile(path)
	if readErr != nil && os.IsNotExist(readErr) && create {
		if err := createSecretAtomically(path); err != nil {
			// Another process may have won the creation race.  In that case read
			// and validate its key; never generate a second key over it.
			if !os.IsExist(err) {
				return nil, err
			}
			data, readErr = os.ReadFile(path)
		} else {
			data, readErr = os.ReadFile(path)
		}
	}
	if readErr != nil {
		if os.IsNotExist(readErr) {
			return nil, fmt.Errorf("%w: %s", ErrSecretMissing, path)
		}
		return nil, fmt.Errorf("read secret file %s: %w", path, readErr)
	}

	if err := checkSecretPermissions(path); err != nil {
		return nil, err
	}
	text := strings.TrimSpace(string(data))
	if len(text) != KeySize*2 {
		return nil, fmt.Errorf("%w: got %d hex characters", ErrSecretFormat, len(text))
	}
	key, err := hex.DecodeString(text)
	if err != nil || len(key) != KeySize {
		return nil, fmt.Errorf("%w", ErrSecretFormat)
	}
	return key, nil
}

func createSecretAtomically(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create secret directory %s: %w", dir, err)
	}

	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return fmt.Errorf("generate shared secret: %w", err)
	}
	encoded := []byte(hex.EncodeToString(key) + "\n")
	// Create a temporary owner-only file in the same directory so rename is
	// atomic on the filesystems used by the supported platforms.
	tmp, err := os.CreateTemp(dir, ".secret.tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary secret file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("set secret permissions: %w", err)
	}
	if _, err := tmp.Write(encoded); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write generated secret: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync generated secret: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close generated secret: %w", err)
	}
	// A plain rename would replace an existing file on POSIX.  That creates a
	// subtle race when two server processes start together: the loser could
	// overwrite the winner's key after the initial existence check.  Installing
	// the temporary inode with a hard link is atomic and fails with EEXIST when a
	// concurrent creator already won; the caller then reads (and validates) the
	// winner's file.
	if err := os.Link(tmpName, path); err != nil {
		return err
	}
	return nil
}

func checkSecretPermissions(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat secret file %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: %s", ErrSecretSymlink, path)
	}
	// Windows does not expose POSIX mode bits as an access-control guarantee;
	// the file is still created owner-only where the platform supports it.
	if runtime.GOOS == "windows" {
		return nil
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("%w: %s has mode %04o; run chmod 600", ErrSecretPermission, path, info.Mode().Perm())
	}
	return nil
}
