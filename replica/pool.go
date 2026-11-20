package replica

import (
	"slices"
	"time"

	"github.com/DanyGoT/diembft/proto/diempb"
)

// pool is the MemPool (DiemBFT 3.6) over the commands submitted to this
// replica. It runs under the replica's lock.
//
// The paper's MemPool hands a command out once. A client here waits for its
// command to commit, and only this replica proposes what was submitted to it,
// so the pool keeps each command until a block of its own carrying it commits,
// and puts it back once that block's proposal can no longer commit.
type pool struct {
	batch, size int
	held        int // queued, handed out or in flight
	queue       []entry
	handout     []entry // taken for a proposal that has not been sent
	inflight    []flight
}

// entry is a submitted command; done closes once it commits.
type entry struct {
	cmd       []byte
	submitted time.Time
	done      chan struct{}
}

// flight is one of this replica's sent proposals.
type flight struct {
	round   uint64
	sent    time.Time
	entries []entry
}

// add queues cmd, or returns false when the pool already holds size commands.
func (p *pool) add(cmd []byte) (<-chan struct{}, bool) {
	if p.held >= p.size {
		return nil, false
	}
	e := entry{cmd: cmd, submitted: time.Now(), done: make(chan struct{})}
	p.queue = append(p.queue, e)
	p.held++
	return e.done, true
}

// GetTransactions is the paper's MemPool.get_transactions (3.6). A previous
// handout that was never sent, because signing the proposal failed, goes back
// first.
func (p *pool) GetTransactions() [][]byte {
	p.requeue(p.handout)
	n := min(p.batch, len(p.queue))
	if n == 0 {
		p.handout = nil
		return nil
	}
	p.handout, p.queue = p.queue[:n:n], p.queue[n:]
	cmds := make([][]byte, n)
	for i, e := range p.handout {
		cmds[i] = e.cmd
	}
	return cmds
}

// proposed records that this replica sent its proposal for round, carrying the
// last handout.
func (p *pool) proposed(round uint64, sent time.Time) {
	p.inflight = append(p.inflight, flight{round: round, sent: sent, entries: p.handout})
	p.handout = nil
}

// committed settles the sent proposals at or below b's round and, if b is this
// replica's, returns its flight and releases its entries. Commit order is
// ancestors first, so any other proposal of this replica's at or below b's
// round is not on the committed chain and never will be: its entries go back
// to the front of the queue, oldest round first.
func (p *pool) committed(b *diempb.Block, self uint32) (own flight, ok bool) {
	var back []entry
	i := 0
	for ; i < len(p.inflight) && p.inflight[i].round <= b.GetRound(); i++ {
		if f := p.inflight[i]; f.round == b.GetRound() && b.GetAuthor() == self {
			own, ok = f, true
		} else {
			back = append(back, f.entries...)
		}
	}
	p.inflight = p.inflight[i:]
	p.requeue(back)
	p.held -= len(own.entries)
	return own, ok
}

func (p *pool) requeue(entries []entry) {
	if len(entries) > 0 {
		p.queue = slices.Concat(entries, p.queue)
	}
}
