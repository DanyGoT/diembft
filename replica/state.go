package replica

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/DanyGoT/diembft/diem"
)

// stateSize is a saved diem.SafetyState: HighestVoteRound, then
// HighestQCRound, each a big-endian uint64.
const stateSize = 16

// loadState reads the counters saved at path. A missing file is a replica
// that has never voted.
func loadState(path string) (diem.SafetyState, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return diem.SafetyState{}, nil
	}
	if err != nil {
		return diem.SafetyState{}, err
	}
	if len(b) != stateSize {
		return diem.SafetyState{}, fmt.Errorf("replica: state file %s holds %d bytes, want %d", path, len(b), stateSize)
	}
	return diem.SafetyState{
		HighestVoteRound: binary.BigEndian.Uint64(b),
		HighestQCRound:   binary.BigEndian.Uint64(b[8:]),
	}, nil
}

// fileStore keeps a replica's safety counters in one file, replaced whole on
// every save.
type fileStore struct{ path string }

// Save is save, logged on failure: the replica then stays silent, and the log
// is the only place that says why.
func (s fileStore) Save(st diem.SafetyState) error {
	err := s.save(st)
	if err != nil {
		slog.Error("replica: cannot save the safety state; not voting", "path", s.path, "err", err)
	}
	return err
}

// save writes st to a temporary file next to path, syncs it and renames it
// over path, then syncs the directory so that the rename survives a crash too.
// A crash at any point leaves either the old state or the new one.
func (s fileStore) save(st diem.SafetyState) error {
	dir := filepath.Dir(s.path)
	f, err := os.CreateTemp(dir, filepath.Base(s.path)+".tmp*")
	if err != nil {
		return err
	}
	b := binary.BigEndian.AppendUint64(make([]byte, 0, stateSize), st.HighestVoteRound)
	b = binary.BigEndian.AppendUint64(b, st.HighestQCRound)
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err == nil {
		err = os.Rename(f.Name(), s.path)
	}
	if err != nil {
		return errors.Join(err, os.Remove(f.Name()))
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}
