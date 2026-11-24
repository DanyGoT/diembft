package replica

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/DanyGoT/diembft/diem"
	"github.com/DanyGoT/diembft/diemcrypto"
)

func TestFileStore(t *testing.T) {
	t.Run("a save replaces the last one and leaves no temp file", func(t *testing.T) {
		dir := t.TempDir()
		s := fileStore{filepath.Join(dir, "state")}
		for _, want := range []diem.SafetyState{{HighestVoteRound: 7, HighestQCRound: 6}, {HighestVoteRound: 9, HighestQCRound: 8}} {
			if err := s.Save(want); err != nil {
				t.Fatalf("Save: %v", err)
			}
			got, err := loadState(s.path)
			if err != nil || got != want {
				t.Fatalf("loadState = %+v, %v, want %+v", got, err, want)
			}
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 1 {
			t.Errorf("dir holds %d files, want only the state file", len(entries))
		}
	})

	t.Run("a missing file is a replica that never voted", func(t *testing.T) {
		got, err := loadState(filepath.Join(t.TempDir(), "state"))
		if err != nil || got != (diem.SafetyState{}) {
			t.Errorf("loadState = %+v, %v, want zero state", got, err)
		}
	})

	t.Run("a file of the wrong size is refused", func(t *testing.T) {
		for _, n := range []int{0, stateSize - 1, stateSize + 1} {
			path := filepath.Join(t.TempDir(), "state")
			if err := os.WriteFile(path, make([]byte, n), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadState(path); err == nil {
				t.Errorf("loadState accepted a %d-byte file", n)
			}
		}
	})
}

// TestNewStateFile: New fails on a state file it cannot read or write, rather
// than start a replica that forgot its votes or cannot save its next one.
func TestNewStateFile(t *testing.T) {
	privs, pubs, err := diemcrypto.GenerateKeys(1)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	corrupt := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(corrupt, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"corrupt":     corrupt,
		"no such dir": filepath.Join(t.TempDir(), "missing", "state"),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := New(Config{
				ID: 1, Key: privs[1], Keys: pubs, StateFile: path,
				Listen: "127.0.0.1:0", Peers: map[uint32]string{1: "127.0.0.1:0"},
			})
			if err == nil {
				t.Error("New = nil error, want one")
			}
		})
	}
}

// TestClusterSavesState: every replica of a running cluster has saved both
// counters to its StateFile.
func TestClusterSavesState(t *testing.T) {
	dir := t.TempDir()
	path := func(id uint32) string { return filepath.Join(dir, fmt.Sprint(id)) }
	reps, run := cluster(t, 4, testRound, func(c *Config) { c.StateFile = path(c.ID) })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { run(ctx); close(done) }()
	committed := waitFor(10*time.Second, func() bool {
		for _, r := range reps {
			if len(r.Log()) < 5 {
				return false
			}
		}
		return true
	})
	cancel()
	<-done
	if !committed {
		t.Fatalf("depths after timeout: %v, want every replica >= 5", depths(reps))
	}

	for _, r := range reps {
		st, err := loadState(path(r.ID()))
		if err != nil || st.HighestVoteRound == 0 || st.HighestQCRound == 0 {
			t.Errorf("replica %d saved %+v, %v, want both counters above 0", r.ID(), st, err)
		}
	}
}
