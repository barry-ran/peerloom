//go:build linux

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestSetupReadRejectsSpecialFiles(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	// This must return immediately without waiting for a FIFO writer.
	if _, err := readSetup(fifo); err == nil {
		t.Fatal("FIFO accepted")
	}
	target := filepath.Join(dir, "valid.json")
	if err := os.WriteFile(target, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readSetup(link); err == nil {
		t.Fatal("symlink accepted")
	}
	if _, err := readSetup(target); err != nil {
		t.Fatal(err)
	}
}

func TestDirectorySyncFailure(t *testing.T) {
	if err := syncOutputDirectory(filepath.Join(t.TempDir(), "missing", "secret")); err == nil {
		t.Fatal("missing output directory accepted")
	}
}
