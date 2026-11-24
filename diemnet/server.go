package diemnet

import (
	"errors"
	"sync"
	"sync/atomic"

	"github.com/DanyGoT/diembft/diem"
	"github.com/DanyGoT/diembft/proto/diempb"
	"github.com/relab/gorums"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

// VerifyInterceptor drops every message accept refuses, from the peer
// ctx.SenderID() names, and counts it in rejected. It runs on the Gorums
// handler goroutine, so messages from different senders are authenticated in
// parallel, before the handler takes the replica's lock.
func VerifyInterceptor(v *diem.Verifier, rejected *atomic.Uint64) gorums.ServerInterceptor {
	return func(ctx gorums.ServerContext, in *gorums.Message, send func(proto.Message), next gorums.Handler) error {
		if !accept(v, ctx.SenderID(), in.Proto) {
			rejected.Add(1)
			return nil
		}
		return next(ctx, in, send)
	}
}

// accept reports whether msg, sent by peer from, may reach its handler. A
// proposal, vote or timeout must name from as its sender, and v must verify
// it. No replica relays another's message, so a mismatch is never legitimate.
// Any other request passes.
func accept(v *diem.Verifier, from uint32, msg proto.Message) bool {
	switch m := msg.(type) {
	case *diempb.ProposalMsg:
		return m.GetSender() == from && v.VerifyProposal(m)
	case *diempb.VoteMsg:
		return m.GetSender() == from && v.VerifyVote(m)
	case *diempb.TimeoutMsg:
		return m.GetTmoInfo().GetSender() == from && v.VerifyTimeout(m)
	}
	return true
}

// handler is the inbound half of the transport. It sees only what
// VerifyInterceptor let through, and calls the core under the replica's lock.
//
// The one-way handlers deliberately do not call ctx.Release(). Gorums holds
// back a sender's next request until the handler returns, and that per-sender
// FIFO is wanted: a leader's proposals must be seen in round order, or a
// proposal arrives before its parent and this replica declines to vote until it
// has fetched the parent.
type handler struct {
	core  *diem.Core
	mu    sync.Locker   // the replica's lock, which serializes every core call
	ready chan struct{} // closed once this replica's peers are connected
}

var _ diempb.DiemServer = (*handler)(nil)

func (h *handler) Proposal(_ gorums.ServerContext, in *diempb.ProposalMsg) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.core.OnProposal(in)
}

func (h *handler) Vote(_ gorums.ServerContext, in *diempb.VoteMsg) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.core.OnVote(in)
}

func (h *handler) Timeout(_ gorums.ServerContext, in *diempb.TimeoutMsg) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.core.OnTimeout(in)
}

var errNoBlock = errors.New("diemnet: block not held")

// RequestBlock answers from the core, which owns the blocks.
func (h *handler) RequestBlock(_ gorums.ServerContext, in *diempb.BlockHash) (*diempb.Block, error) {
	h.mu.Lock()
	b := h.core.Block(in.GetId())
	h.mu.Unlock()
	if b == nil {
		return nil, errNoBlock
	}
	return b, nil
}

// Ready answers once this replica is ready. It takes no lock: the replica
// holds it until it has passed the barrier.
func (h *handler) Ready(ctx gorums.ServerContext, _ *emptypb.Empty) (*emptypb.Empty, error) {
	select {
	case <-h.ready:
		return &emptypb.Empty{}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// block hands a fetched block to the core.
func (h *handler) block(b *diempb.Block) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.core.OnBlock(b)
}
