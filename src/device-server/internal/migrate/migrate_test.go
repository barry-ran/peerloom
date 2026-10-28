package migrate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("000001_initial.up.sql", "SELECT 1;")
	write("000001_initial.down.sql", "SELECT 2;")
	ms, err := Load(dir)
	if err != nil || len(ms) != 1 || ms[0].Version != 1 {
		t.Fatalf("load failed: %v", err)
	}
	first := ms[0].Checksum
	write("000001_initial.down.sql", "SELECT 3;")
	ms, err = Load(dir)
	if err != nil || ms[0].Checksum == first {
		t.Fatal("down changes not checksummed")
	}
	write("000003_gap.up.sql", "SELECT 1;")
	write("000003_gap.down.sql", "SELECT 1;")
	if _, err = Load(dir); err == nil {
		t.Fatal("accepted migration gap")
	}
}
func TestMissingDown(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "000001_initial.up.sql"), []byte("SELECT 1;"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("accepted missing rollback")
	}
}
