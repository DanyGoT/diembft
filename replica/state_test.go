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

// reopen is a restart: it opens the state file at path afresh.
func reopen(t *testing.T, path string) (diem.SafetyState, *fileStore) {
	t.Helper()
	st, s, err := openState(path)
	if err != nil {
		t.Fatalf("openState: %v", err)
	}
	t.Cleanup(func() { _ = s.f.Close() })
	return st, s
}

// tear damages the slot the last save on s wrote, as a crash during it would.
func tear(t *testing.T, s *fileStore) {
	t.Helper()
	if _, err := s.f.WriteAt([]byte{0xff}, int64(s.next^1)*slotStride); err != nil {
		t.Fatal(err)
	}
}

func TestFileStore(t *testing.T) {
	a := diem.SafetyState{HighestVoteRound: 7, HighestQCRound: 6}
	b := diem.SafetyState{HighestVoteRound: 9, HighestQCRound: 8}
	c := diem.SafetyState{HighestVoteRound: 11, HighestQCRound: 10}

	t.Run("a missing file is created holding the zero state", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "state")
		if st, _ := reopen(t, path); st != (diem.SafetyState{}) {
			t.Errorf("openState = %+v, want zero state", st)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 1 {
			t.Errorf("dir holds %d files, want only the state file", len(entries))
		}
	})

	t.Run("a restart gets the last save back", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state")
		for _, want := range []diem.SafetyState{a, b, c} {
			_, s := reopen(t, path)
			if err := s.Save(want); err != nil {
				t.Fatalf("Save: %v", err)
			}
			if got, _ := reopen(t, path); got != want {
				t.Fatalf("openState = %+v, want %+v", got, want)
			}
		}
	})

	t.Run("a torn save falls back to the one before", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "state")
		_, s := reopen(t, path)
		for _, st := range []diem.SafetyState{a, b} {
			if err := s.Save(st); err != nil {
				t.Fatalf("Save: %v", err)
			}
		}
		// After a restart the next save must go to a's slot, not over b.
		_, s = reopen(t, path)
		if err := s.Save(c); err != nil {
			t.Fatalf("Save: %v", err)
		}
		tear(t, s)
		if got, _ := reopen(t, path); got != b {
			t.Errorf("openState = %+v, want %+v", got, b)
		}
	})

	t.Run("a file of the wrong size or with no valid slot is refused", func(t *testing.T) {
		for _, n := range []int{0, slotSize, fileSize - 1, fileSize, fileSize + 1} {
			path := filepath.Join(t.TempDir(), "state")
			if err := os.WriteFile(path, make([]byte, n), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := openState(path); err == nil {
				t.Errorf("openState accepted a %d-byte file of zeros", n)
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
// counters to its StateFile. Replica 1 starts from counters far ahead, as if
// restarted, so it must load them and then never vote or time out: its file
// still holds them at the end.
func TestClusterSavesState(t *testing.T) {
	dir := t.TempDir()
	path := func(id uint32) string { return filepath.Join(dir, fmt.Sprint(id)) }
	ahead := diem.SafetyState{HighestVoteRound: 1 << 40, HighestQCRound: 1<<40 - 1}
	_, s := reopen(t, path(1))
	if err := s.Save(ahead); err != nil {
		t.Fatalf("Save: %v", err)
	}
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
		st, _ := reopen(t, path(r.ID()))
		switch {
		case r.ID() == 1 && st != ahead:
			t.Errorf("replica 1 saved %+v, want the %+v it started from", st, ahead)
		case st.HighestVoteRound == 0 || st.HighestQCRound == 0:
			t.Errorf("replica %d saved %+v, want both counters above 0", r.ID(), st)
		}
	}
}
