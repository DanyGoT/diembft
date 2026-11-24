package replica

import (
	"errors"

	"github.com/DanyGoT/diembft/proto/diempb"
)

var (
	errCommitted = errors.New("replica: command already committed")
	errFull      = errors.New("replica: too many commands waiting")
)

// Pending is a submitted command. Done closes once it commits, and Proof is
// then the proof.
type Pending struct {
	done   chan struct{}
	proof  *diempb.CommitProof
	refs   int  // the callers waiting on it
	pooled bool // in this replica's pool, which keeps it until it commits
}

func (p *Pending) Done() <-chan struct{}      { return p.done }
func (p *Pending) Proof() *diempb.CommitProof { return p.proof }

type cmdKey struct{ client, seq uint64 }

// waiters holds the submitted commands until they commit, in any replica's
// block. It runs under the replica's lock.
//
// A client has one command in flight, so its commands commit in seq order, and
// last is all a replica keeps to drop a command it has already committed, as
// PBFT keeps one timestamp per client.
type waiters struct {
	size    int
	pending map[cmdKey]*Pending
	last    map[uint64]uint64 // the highest committed seq, by client
}

func newWaiters(size int) *waiters {
	return &waiters{size: size, pending: map[cmdKey]*Pending{}, last: map[uint64]uint64{}}
}

// add returns the Pending for cmd, and fresh if it was not held already. It
// refuses a command at or below its client's last committed seq,
// seq 0 included, and a new one when size commands are waiting.
func (w *waiters) add(cmd *diempb.Command) (p *Pending, fresh bool, err error) {
	if cmd.GetSeq() <= w.last[cmd.GetClient()] {
		return nil, false, errCommitted
	}
	k := cmdKey{cmd.GetClient(), cmd.GetSeq()}
	if p := w.pending[k]; p != nil {
		p.refs++
		return p, false, nil
	}
	if len(w.pending) >= w.size {
		return nil, false, errFull
	}
	p = &Pending{done: make(chan struct{}), refs: 1}
	w.pending[k] = p
	return p, true, nil
}

// drop is one caller giving up on cmd. Its Pending goes once no one waits on
// it, unless the pool holds cmd: the Pending then stays until cmd commits, so
// cmd submitted again joins it rather than entering the pool twice.
func (w *waiters) drop(cmd *diempb.Command, p *Pending) {
	k := cmdKey{cmd.GetClient(), cmd.GetSeq()}
	p.refs--
	if w.pending[k] == p && p.refs == 0 && !p.pooled {
		delete(w.pending, k)
	}
}

// committed settles every command in chain, which qc committed, and returns
// how many committed for the first time. A command repeated in a later entry
// or block is not counted again.
func (w *waiters) committed(chain []*diempb.Block, qc *diempb.QuorumCert) (fresh uint64) {
	for i, b := range chain {
		var proof *diempb.CommitProof
		for _, entry := range b.GetPayload() {
			client, seq, ok := diempb.CommandID(entry)
			if !ok || seq <= w.last[client] {
				continue
			}
			w.last[client] = seq
			fresh++
			k := cmdKey{client, seq}
			p := w.pending[k]
			if p == nil {
				continue
			}
			if proof == nil {
				proof = diempb.CommitProof_builder{Blocks: chain[i:], Qc: qc}.Build()
			}
			p.proof = proof
			close(p.done)
			delete(w.pending, k)
		}
	}
	return fresh
}
