package replica

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"

	"github.com/DanyGoT/diembft/diem"
)

// A state file holds two slots a page apart, so a write torn by a crash
// damages only the slot it was writing. Saves alternate between the slots and
// overwrite them in place, one synced write each, and opening takes the newer
// valid slot. A slot is HighestVoteRound, HighestQCRound and the CRC-32C of
// both, big-endian.
const (
	slotStride = 4096
	slotSize   = 20
	fileSize   = 2 * slotStride
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

func encodeSlot(st diem.SafetyState) []byte {
	b := binary.BigEndian.AppendUint64(make([]byte, 0, slotSize), st.HighestVoteRound)
	b = binary.BigEndian.AppendUint64(b, st.HighestQCRound)
	return binary.BigEndian.AppendUint32(b, crc32.Checksum(b, castagnoli))
}

func decodeSlot(b []byte) (diem.SafetyState, bool) {
	if crc32.Checksum(b[:16], castagnoli) != binary.BigEndian.Uint32(b[16:slotSize]) {
		return diem.SafetyState{}, false
	}
	return diem.SafetyState{
		HighestVoteRound: binary.BigEndian.Uint64(b),
		HighestQCRound:   binary.BigEndian.Uint64(b[8:]),
	}, true
}

// fileStore keeps a replica's safety counters in a state file.
type fileStore struct {
	path string
	f    *os.File
	next int // the slot the next save writes: never the one holding the latest state
}

// openState opens the state file at path and returns the counters saved there.
// A missing file is a replica that has never voted, and is created.
func openState(path string) (diem.SafetyState, *fileStore, error) {
	var zero diem.SafetyState
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		if err := create(path); err != nil {
			return zero, nil, err
		}
	}
	f, err := os.OpenFile(path, os.O_RDWR|syscall.O_DSYNC, 0)
	if err != nil {
		return zero, nil, err
	}
	b := make([]byte, fileSize+1)
	if n, err := f.ReadAt(b, 0); n != fileSize {
		err = fmt.Errorf("replica: state file %s holds %d bytes, want %d: %w", path, n, fileSize, err)
		return zero, nil, errors.Join(err, f.Close())
	}
	a, okA := decodeSlot(b)
	c, okC := decodeSlot(b[slotStride:])
	switch {
	case okA && (!okC || newer(a, c)):
		return a, &fileStore{path, f, 1}, nil
	case okC:
		return c, &fileStore{path, f, 0}, nil
	}
	return zero, nil, errors.Join(fmt.Errorf("replica: state file %s holds no valid slot", path), f.Close())
}

// newer reports whether a was saved after b. Both counters only grow, so the
// later save has both at least as high.
func newer(a, b diem.SafetyState) bool {
	return a.HighestVoteRound > b.HighestVoteRound ||
		a.HighestVoteRound == b.HighestVoteRound && a.HighestQCRound >= b.HighestQCRound
}

// create writes a state file holding the zero state through a temporary file,
// renamed into place and synced, so a crash leaves either no file or a whole
// one.
func create(path string) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	_, err = f.Write(append(encodeSlot(diem.SafetyState{}), make([]byte, fileSize-slotSize)...))
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		return errors.Join(err, os.Remove(f.Name()))
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}

// Save is save, logged on failure: the replica then stays silent, and the log
// is the only place that says why.
func (s *fileStore) Save(st diem.SafetyState) error {
	err := s.save(st)
	if err != nil {
		slog.Error("replica: cannot save the safety state; not voting", "path", s.path, "err", err)
	}
	return err
}

// save writes st over the older slot. The file is opened O_DSYNC, so the write
// returns once st is on disk. A failed write leaves next where it was, so the
// retry writes the same slot and the latest state stays untouched.
func (s *fileStore) save(st diem.SafetyState) error {
	if _, err := s.f.WriteAt(encodeSlot(st), int64(s.next)*slotStride); err != nil {
		return err
	}
	s.next ^= 1
	return nil
}
