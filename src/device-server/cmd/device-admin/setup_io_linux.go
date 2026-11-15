//go:build linux

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// Paths must be in an operator-owned private directory. NOFOLLOW protects the
// final component; NONBLOCK ensures a substituted FIFO cannot stall inspection.
func openSetupInput(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		f.Close()
		if err != nil {
			return nil, err
		}
		return nil, errors.New("setup input must be a regular file")
	}
	return f, nil
}

func syncOutputDirectory(path string) error {
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
