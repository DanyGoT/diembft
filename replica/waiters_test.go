package replica

import (
	"errors"
	"testing"

	"github.com/DanyGoT/diembft/proto/diempb"
)

func carrying(round uint64, cmds ...*diempb.Command) *diempb.Block {
	payload := make([][]byte, len(cmds))
	for i, c := range cmds {
		payload[i] = c.Encode()
	}
	return diempb.Block_builder{Round: round, Payload: payload}.Build()
}

func mustAdd(t *testing.T, w *waiters, cmd *diempb.Command) *Pending {
	t.Helper()
	p, _, err := w.add(cmd)
	if err != nil {
		t.Fatalf("add(%v): %v", cmd, err)
	}
	return p
}

func closed(p *Pending) bool {
	select {
	case <-p.Done():
		return true
	default:
		return false
	}
}

// TestWaitersSettleFromAnyBlock pins that a commit settles every waiting
// command in the chain, whoever proposed its block, with a proof that starts
// at the command's own block and ends with the committing certificate.
func TestWaitersSettleFromAnyBlock(t *testing.T) {
	w := newWaiters(8)
	a, b := command(1, 1), command(2, 1)
	pa, pb := mustAdd(t, w, a), mustAdd(t, w, b)
	chain := []*diempb.Block{carrying(3, a), carrying(4, b)}
	qc := diempb.QuorumCert_builder{}.Build()

	if got := w.committed(chain, qc); got != 2 {
		t.Errorf("committed = %d, want 2", got)
	}
	if !closed(pa) || !closed(pb) {
		t.Fatal("a committed command's Pending is still open")
	}
	if got := pa.Proof().GetBlocks(); len(got) != 2 || got[0] != chain[0] {
		t.Errorf("proof of a starts at round %d with %d blocks, want round 3 with 2", got[0].GetRound(), len(got))
	}
	if got := pb.Proof().GetBlocks(); len(got) != 1 || got[0] != chain[1] {
		t.Errorf("proof of b has %d blocks, want only its own", len(got))
	}
	if pa.Proof().GetQc() != qc {
		t.Error("the proof does not carry the committing certificate")
	}
	if len(w.pending) != 0 {
		t.Errorf("%d commands still waiting", len(w.pending))
	}
}

// TestWaitersDropDuplicates pins the per-client last seq: a command submitted
// twice shares one Pending, a command committed twice counts once, and a
// command at or below its client's last committed seq is refused.
func TestWaitersDropDuplicates(t *testing.T) {
	w := newWaiters(8)
	a := command(1, 1)
	p, fresh, _ := w.add(a)
	if again, freshAgain, _ := w.add(a); again != p || !fresh || freshAgain {
		t.Fatal("a command submitted twice did not share its Pending")
	}

	chain := []*diempb.Block{carrying(3, a, a), carrying(4, a)}
	if got := w.committed(chain, nil); got != 1 {
		t.Errorf("a command repeated in the chain counted %d times, want 1", got)
	}
	for _, cmd := range []*diempb.Command{a, command(1, 0), command(2, 0)} {
		if _, _, err := w.add(cmd); !errors.Is(err, errCommitted) {
			t.Errorf("add(%v) = %v, want errCommitted", cmd, err)
		}
	}
	if _, _, err := w.add(command(1, 2)); err != nil {
		t.Errorf("the client's next command was refused: %v", err)
	}
}

// TestWaitersBounded pins that a replica holds at most size waiting commands,
// and that one dropped makes room.
func TestWaitersBounded(t *testing.T) {
	w := newWaiters(1)
	a := command(1, 1)
	p := mustAdd(t, w, a)
	if _, _, err := w.add(command(2, 1)); !errors.Is(err, errFull) {
		t.Fatalf("add past size = %v, want errFull", err)
	}
	w.drop(a, p)
	mustAdd(t, w, command(2, 1))
}
