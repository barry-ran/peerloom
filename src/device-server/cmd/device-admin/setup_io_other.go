//go:build !linux

package main

import (
	"errors"
	"os"
)

// Non-Linux inspection requires a trusted operator-owned parent directory.
// Validate before open (avoids ordinary special files) and afterwards; this is
// not a defense against an adversary able to replace entries in that directory.
func openSetupInput(path string) (*os.File, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("setup input must be a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	actual, err := f.Stat()
	if err != nil || !actual.Mode().IsRegular() || !os.SameFile(st, actual) {
		f.Close()
		return nil, errors.New("setup input changed or is not a regular file")
	}
	return f, nil
}

func syncOutputDirectory(path string) error {
	return errors.New("durable secret output requires Linux directory fsync; run device-admin in the deployment container")
}
