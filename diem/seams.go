package diem

import (
	"time"

	"github.com/DanyGoT/diembft/proto/diempb"
)

// Transport is the outbound half of the network. Every method is safe to call
// inside a core call and returns no error: a BFT replica cannot act on a send
// failure, and the round timer is the recovery mechanism. A method returns once
// the message is queued, and blocks only while a recipient's queue is full.
type Transport interface {
	// Proposal sends to all replicas, this one included.
	Proposal(*diempb.ProposalMsg)
	// Vote sends to one replica: the leader of the next round. This is the
	// paper's unicast, and it is why only that leader accumulates a QC.
	Vote(*diempb.VoteMsg, uint32)
	// Timeout sends to all replicas, this one included.
	Timeout(*diempb.TimeoutMsg)
	// RequestBlock asks every replica for the block with id. The block, if one
	// comes back, arrives through Core.OnBlock.
	RequestBlock(id []byte)
}

// Crypto signs and verifies digests. DiemBFT aggregates nothing, so a
// certificate is a slice of signatures and there is no combine step.
type Crypto interface {
	Sign(digest []byte) ([]byte, error)
	// Verify checks sig against the public key registered for signer.
	Verify(signer uint32, digest, sig []byte) bool
	// VerifyAll reports whether sigs[i] is a valid signature over digests[i]
	// by signers[i] for every i. It may check them side by side, which is why
	// it sits behind Crypto: this package starts no goroutines.
	VerifyAll(signers []uint32, digests, sigs [][]byte) bool
}

// MemPool is the paper's MemPool module (3.6). GetTransactions runs under
// Config.Lock and must not block. An empty result still produces a block,
// since the pipeline is what commits the blocks below it.
type MemPool interface {
	GetTransactions() [][]byte
}

// Clock is the time source. The deterministic harness supplies a fake one.
type Clock interface {
	Now() time.Time
	AfterFunc(time.Duration, func()) Timer
}

// Timer is a pending Clock.AfterFunc callback.
type Timer interface{ Stop() bool }

// SystemClock is the wall-clock Clock.
type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now() }

func (SystemClock) AfterFunc(d time.Duration, f func()) Timer { return time.AfterFunc(d, f) }

// SafetyState is Safety's two counters (3.4), the state a replica must not
// lose across a restart: a replica that forgets them can vote twice in a round.
type SafetyState struct {
	HighestVoteRound uint64
	HighestQCRound   uint64
}

// SafetyStore keeps SafetyState across restarts. Save runs under Config.Lock
// before every vote or timeout that raises a counter, and returns only once
// the state would survive a crash.
type SafetyStore interface {
	Save(SafetyState) error
}
