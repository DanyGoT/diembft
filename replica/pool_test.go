package replica

import (
	"slices"
	"testing"
	"time"

	"github.com/DanyGoT/diembft/proto/diempb"
)

const self = 1

func block(author uint32, round uint64) *diempb.Block {
	return diempb.Block_builder{Author: author, Round: round}.Build()
}

func cmds(names ...string) [][]byte {
	out := make([][]byte, len(names))
	for i, n := range names {
		out[i] = []byte(n)
	}
	return out
}

func newPool(batch int, names ...string) *pool {
	p := &pool{batch: batch}
	for _, c := range cmds(names...) {
		p.add(c)
	}
	return p
}

func wantQueue(t *testing.T, p *pool, names ...string) {
	t.Helper()
	if !slices.EqualFunc(p.queue, cmds(names...), slices.Equal) {
		t.Errorf("queue = %q, want %q", p.queue, names)
	}
}

// TestPoolRequeuesAbandonedProposals pins that commands in proposals that can
// no longer commit go back to the front of the queue, oldest round first.
func TestPoolRequeuesAbandonedProposals(t *testing.T) {
	p := newPool(2, "a", "b", "c", "d", "e")
	p.GetTransactions()
	p.proposed(5, time.Now())
	p.GetTransactions()
	p.proposed(7, time.Now())

	if _, own := p.committed(block(2, 8), self); own {
		t.Error("a block by another author reported as own")
	}
	wantQueue(t, p, "a", "b", "c", "d", "e")
	if len(p.inflight) != 0 {
		t.Errorf("inflight = %v, want empty", p.inflight)
	}
}

// TestPoolKeepsCommittedAncestors pins that an own proposal committed as an
// ancestor is settled, not requeued, when a later block commits after it, and
// that a proposal above the committed round stays in flight.
func TestPoolKeepsCommittedAncestors(t *testing.T) {
	p := newPool(1, "a", "b", "c")
	sent := time.Now()
	p.GetTransactions()
	p.proposed(5, sent)
	p.GetTransactions()
	p.proposed(7, time.Now())
	p.GetTransactions()
	p.proposed(9, time.Now())

	if got, own := p.committed(block(self, 5), self); !own || !got.Equal(sent) {
		t.Errorf("committed(own round 5) = %v, %v, want %v, true", got, own, sent)
	}
	p.committed(block(2, 8), self)
	wantQueue(t, p, "b")
	if len(p.inflight) != 1 || p.inflight[0].round != 9 {
		t.Errorf("inflight = %v, want round 9 only", p.inflight)
	}
}

// TestPoolRequeuesUnsentHandout pins that a handout whose proposal was never
// sent, because signing failed, is handed out again.
func TestPoolRequeuesUnsentHandout(t *testing.T) {
	p := newPool(1, "a", "b")
	p.GetTransactions()
	if got := p.GetTransactions(); !slices.EqualFunc(got, cmds("a"), slices.Equal) {
		t.Errorf("second handout = %q, want [a]", got)
	}
}
