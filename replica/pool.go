package replica

import (
	"slices"
	"time"

	"github.com/DanyGoT/diembft/proto/diempb"
)

// pool is the MemPool (DiemBFT 3.6) over the commands clients submit to this
// replica. It runs under the replica's lock.
//
// The paper's MemPool hands a command out once. A client here waits for its
// command to commit, so the pool keeps what it handed out until the command
// commits, and puts it back once its proposal can no longer commit.
type pool struct {
	batch    int
	queue    [][]byte
	handout  [][]byte // taken for a proposal that has not been sent
	inflight []flight // sent proposals, rounds ascending
}

// flight is one of this replica's sent proposals.
type flight struct {
	round uint64
	sent  time.Time
	cmds  [][]byte
}

func (p *pool) add(cmd []byte) { p.queue = append(p.queue, cmd) }

// GetTransactions is the paper's MemPool.get_transactions (3.6). A previous
// handout that was never sent, because signing the proposal failed, goes back
// first.
func (p *pool) GetTransactions() [][]byte {
	p.requeue(p.handout)
	n := min(p.batch, len(p.queue))
	p.handout, p.queue = p.queue[:n:n], p.queue[n:]
	if n == 0 {
		p.handout = nil
	}
	return p.handout
}

// proposed records that this replica sent its proposal for round, carrying the
// last handout.
func (p *pool) proposed(round uint64, sent time.Time) {
	p.inflight = append(p.inflight, flight{round: round, sent: sent, cmds: p.handout})
	p.handout = nil
}

// committed settles the sent proposals at or below b's round, and reports when
// b was sent if this replica proposed it. Commit order is ancestors first, so
// any other proposal of this replica's at or below b's round is not on the
// committed chain and never will be: its commands go back to the front of the
// queue, oldest round first.
func (p *pool) committed(b *diempb.Block, self uint32) (sent time.Time, own bool) {
	var back [][]byte
	i := 0
	for ; i < len(p.inflight) && p.inflight[i].round <= b.GetRound(); i++ {
		f := p.inflight[i]
		if f.round == b.GetRound() && b.GetAuthor() == self {
			sent, own = f.sent, true
			continue
		}
		back = append(back, f.cmds...)
	}
	p.inflight = p.inflight[i:]
	p.requeue(back)
	return sent, own
}

func (p *pool) requeue(cmds [][]byte) {
	if len(cmds) > 0 {
		p.queue = slices.Concat(cmds, p.queue)
	}
}
