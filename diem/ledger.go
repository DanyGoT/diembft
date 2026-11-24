package diem

import (
	"slices"

	"github.com/DanyGoT/diembft/proto/diempb"
)

// MemLedger is the in-memory ledger (paper 3.2): a branching tree of
// speculative states extending the last committed one, plus the committed
// blocks a lagging peer may still fetch.
//
// The speculation tree is what lets a vote certify an execution result and not
// just an ordering. A replica whose VM diverges speculates a different state
// id, so its vote aggregates under a different key and never joins the quorum —
// the divergence shows up as a stalled round rather than as silent corruption.
type MemLedger struct {
	// Execute is the VM. It must be deterministic across replicas; that is the
	// whole assumption DiemBFT's execution certification rests on.
	Execute func(prev []byte, payload [][]byte) []byte

	// OnCommit, if set, runs once per commit with the blocks it exported,
	// oldest first, and the certificate that committed the last of them. It is
	// where a replicated application consumes the chain; the paper leaves it to
	// the "higher level logic" the Ledger module is the gateway for.
	OnCommit func(chain []*diempb.Block, qc *diempb.QuorumCert)

	// History bounds the committed blocks kept for peers that fetch a block
	// they missed. A persistent ledger store would keep them all; this one is
	// a prototype and must not grow without bound during a long run.
	History int

	pending   map[string]speculated
	held      map[string]*diempb.Block // waiting on a parent not yet speculated
	committed map[string]*diempb.Block
	order     []string // committed ids, oldest first

	commitID    string
	commitState []byte
}

type speculated struct {
	block *diempb.Block
	state []byte
}

const defaultHistory = 512

// NewMemLedger returns a ledger with genesis committed. Genesis gets a
// non-zero state id on purpose: a zero CommitStateID is the paper's bottom,
// so a genesis state of zero would make the first commit indistinguishable
// from no commit at all.
func NewMemLedger() *MemLedger {
	l := &MemLedger{
		Execute:   ExecuteHash,
		History:   defaultHistory,
		pending:   map[string]speculated{},
		held:      map[string]*diempb.Block{},
		committed: map[string]*diempb.Block{},
	}
	l.commitID = string(genesisBlock.GetId())
	l.commitState = ExecuteHash(zeroHash[:], nil)
	l.committed[l.commitID] = genesisBlock
	l.order = append(l.order, l.commitID)
	return l
}

// Speculate executes b over its parent's state, then every held block that was
// waiting on b. A parent this replica never speculated returns the zero state,
// and b is held until the parent arrives, unless the parent is at or below the
// commit frontier, where it can never arrive.
//
// DiemBFT section 3 defines no way to fetch a block; the core fetches the
// parent of a held block, and this is where it lands. Until it does,
// PendingState reports false and Safety declines to vote —
// Safety.DeclinedMissingAncestor counts what that costs.
//
// The paper's signature is speculate(prev_block_id, block_id, txns). All
// three are fields of b, and committed_block must hand a whole block back,
// so the ledger has to hold the block in any case.
func (l *MemLedger) Speculate(b *diempb.Block) []byte {
	prev, ok := l.PendingState(b.ParentID())
	if !ok {
		if b.GetQc().Round() > l.commitRound() {
			l.held[string(b.GetId())] = b
		}
		return zeroHash[:]
	}
	id := string(b.GetId())
	state := l.Execute(prev, b.GetPayload())
	l.pending[id] = speculated{block: b, state: state}
	for hid, h := range l.held {
		if string(h.ParentID()) == id {
			delete(l.held, hid)
			l.Speculate(h)
		}
	}
	return state
}

// Missing is the oldest ancestor of a held block that this ledger has never
// seen, or nil if the block is not held.
func (l *MemLedger) Missing(blockID []byte) []byte {
	b, ok := l.held[string(blockID)]
	if !ok {
		return nil
	}
	for {
		parent := b.ParentID()
		if b, ok = l.held[string(parent)]; !ok {
			return parent
		}
	}
}

// Known reports whether the block is held, speculated or committed here.
func (l *MemLedger) Known(blockID []byte) bool {
	_, held := l.held[string(blockID)]
	_, pending := l.pending[string(blockID)]
	_, committed := l.committed[string(blockID)]
	return held || pending || committed
}

func (l *MemLedger) commitRound() uint64 { return l.committed[l.commitID].GetRound() }

// PendingState is the speculated state for a block. The last committed block
// answers too: its children extend it, and it is no longer pending.
func (l *MemLedger) PendingState(blockID []byte) ([]byte, bool) {
	if string(blockID) == l.commitID {
		return l.commitState, true
	}
	s, ok := l.pending[string(blockID)]
	return s.state, ok
}

// Commit exports the pending prefix ending at the block qc commits, its
// vote's parent, and discards the branches forking below it.
func (l *MemLedger) Commit(qc *diempb.QuorumCert) {
	blockID := qc.GetVoteInfo().GetParentId()
	if string(blockID) == l.commitID {
		return // already committed; the common case, since every QC re-commits
	}
	// Walk back to the commit frontier, then apply forward so the ledger sees
	// commit order.
	var chain []speculated
	for id := string(blockID); id != l.commitID; {
		s, ok := l.pending[id]
		if !ok {
			return // blockID is not a descendant of the frontier: nothing to do
		}
		chain = append(chain, s)
		id = string(s.block.ParentID())
	}
	blocks := make([]*diempb.Block, len(chain))
	for i, s := range slices.Backward(chain) {
		id := string(s.block.GetId())
		delete(l.pending, id)
		l.committed[id] = s.block
		l.order = append(l.order, id)
		l.commitID, l.commitState = id, s.state
		blocks[len(chain)-1-i] = s.block
	}
	if l.OnCommit != nil {
		l.OnCommit(blocks, qc)
	}
	l.prune()
	l.forget()
}

// CommittedBlock returns a committed block by id.
func (l *MemLedger) CommittedBlock(blockID []byte) (*diempb.Block, bool) {
	b, ok := l.committed[string(blockID)]
	return b, ok
}

// prune drops speculated states that can no longer be reached from the commit
// frontier. A block survives only while its parent does, so deleting the
// orphans repeatedly until nothing changes removes whole abandoned branches.
// A held block goes once its parent falls to the frontier or below.
func (l *MemLedger) prune() {
	for id, b := range l.held {
		if b.GetQc().Round() <= l.commitRound() {
			delete(l.held, id)
		}
	}
	for changed := true; changed; {
		changed = false
		for id, s := range l.pending {
			parent := string(s.block.ParentID())
			if parent == l.commitID {
				continue
			}
			if _, ok := l.pending[parent]; !ok {
				delete(l.pending, id)
				changed = true
			}
		}
	}
}

// forget drops the oldest committed blocks past the retention bound.
func (l *MemLedger) forget() {
	for len(l.order) > l.History {
		id := l.order[0]
		l.order = l.order[1:]
		if id != l.commitID {
			delete(l.committed, id)
		}
	}
}
