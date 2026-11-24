package diem

import (
	"bytes"
	"errors"
	"testing"

	"github.com/DanyGoT/diembft/proto/diempb"
)

// testN and testQuorum give a 4-replica group (f=1, quorum=2f+1=3), matching
// QuorumSize(testN).
const (
	testN      = 4
	testQuorum = 3
)

// safetyFixture bundles a Safety module with the ledger and block tree it was
// built over, so a test can reach into the ledger without re-deriving it.
type safetyFixture struct {
	safety *Safety
	ledger *MemLedger
	crypto Crypto
}

func newSafetyFixture(id uint32) *safetyFixture {
	ledger := NewMemLedger()
	crypto := newTestSigner(testN)
	tree := NewBlockTree(id, testQuorum, ledger, crypto)
	return &safetyFixture{
		safety: NewSafety(id, crypto, ledger, tree),
		ledger: ledger,
		crypto: crypto,
	}
}

// signAs signs digest as replica id. testSigner never fails to sign.
func signAs(id uint32, digest []byte) *diempb.Signature {
	sig, _ := sign(newTestSigner(testN), id, digest)
	return sig
}

// makeTC builds a TC for round out of one timeout vote per entry in
// highQCRounds, signed by replicas 1..len(highQCRounds).
func makeTC(round uint64, highQCRounds ...uint64) *diempb.TimeoutCert {
	votes := make([]*diempb.TimeoutVote, len(highQCRounds))
	for i, r := range highQCRounds {
		votes[i] = diempb.TimeoutVote_builder{
			HighQcRound: r,
			Sig:         signAs(uint32(i+1), diempb.TimeoutDigest(round, r)),
		}.Build()
	}
	return diempb.TimeoutCert_builder{Round: round, Votes: votes}.Build()
}

// makeQC builds a QC over vi whose LedgerCommitInfo is correctly bound to it,
// signed by signerIDs and assembled by the first of them.
func makeQC(vi *diempb.VoteInfo, commitStateID []byte, signerIDs ...uint32) *diempb.QuorumCert {
	return makeQCWith(signAs, vi, commitStateID, signerIDs...)
}

// makeQCWith is makeQC signing through signAs.
func makeQCWith(signAs func(uint32, []byte) *diempb.Signature, vi *diempb.VoteInfo, commitStateID []byte, signerIDs ...uint32) *diempb.QuorumCert {
	commit := commitInfo(commitStateID, vi)
	digest := commit.Digest()
	sigs := make([]*diempb.Signature, len(signerIDs))
	for i, id := range signerIDs {
		sigs[i] = signAs(id, digest)
	}
	author := signerIDs[0]
	qc := diempb.QuorumCert_builder{
		VoteInfo:         vi,
		LedgerCommitInfo: commit,
		Signatures:       sigs,
		Author:           author,
	}.Build()
	qc.SetAuthorSig(signAs(author, qc.SigsDigest()))
	return qc
}

func TestConsecutive(t *testing.T) {
	tests := []struct {
		name              string
		blockRound, round uint64
		want              bool
	}{
		{"consecutive", 5, 4, true},
		{"gap", 5, 3, false},
		{"same round", 5, 5, false},
		{"genesis boundary", 1, 0, true},
		{"block round below", 3, 4, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := consecutive(tt.blockRound, tt.round); got != tt.want {
				t.Errorf("consecutive(%d, %d) = %v, want %v", tt.blockRound, tt.round, got, tt.want)
			}
		})
	}
}

func TestSafeToExtend(t *testing.T) {
	f := newSafetyFixture(1)
	tests := []struct {
		name                string
		blockRound, qcRound uint64
		tc                  *diempb.TimeoutCert
		want                bool
	}{
		{"nil tc", 11, 5, nil, false},
		{"non-consecutive tc round", 12, 5, makeTC(10, 3, 4, 5), false},
		{"qc round below max high qc round", 11, 4, makeTC(10, 3, 4, 5), false},
		{"qc round at max high qc round", 11, 5, makeTC(10, 3, 4, 5), true},
		{"qc round above max high qc round", 11, 6, makeTC(10, 3, 4, 5), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := f.safety.safeToExtend(tt.blockRound, tt.qcRound, tt.tc); got != tt.want {
				t.Errorf("safeToExtend(%d, %d, tc) = %v, want %v", tt.blockRound, tt.qcRound, got, tt.want)
			}
		})
	}
}

func TestSafeToVote(t *testing.T) {
	tests := []struct {
		name             string
		highestVoteRound uint64
		blockRound       uint64
		qcRound          uint64
		tc               *diempb.TimeoutCert
		want             bool
	}{
		{"monotonic round rejected", 5, 5, 3, nil, false},
		{"must extend a smaller round", 0, 5, 5, nil, false},
		{"consecutive qc accepted", 0, 6, 5, nil, true},
		{"tc justifies the gap", 0, 11, 6, makeTC(10, 3, 4, 6), true},
		{"tc round not directly below block round rejected", 0, 11, 6, makeTC(9, 3, 4, 6), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newSafetyFixture(1)
			f.safety.highestVoteRound = tt.highestVoteRound
			if got := f.safety.safeToVote(tt.blockRound, tt.qcRound, tt.tc); got != tt.want {
				t.Errorf("safeToVote(%d, %d, tc) = %v, want %v", tt.blockRound, tt.qcRound, got, tt.want)
			}
		})
	}
}

func TestSafeToTimeout(t *testing.T) {
	tests := []struct {
		name             string
		highestQCRound   uint64
		highestVoteRound uint64
		round            uint64
		qcRound          uint64
		tc               *diempb.TimeoutCert
		want             bool
	}{
		{"qc round below highest qc round rejected", 5, 0, 10, 4, nil, false},
		{"highest-vote-round-1 boundary rejected", 0, 5, 4, 0, nil, false},
		{"above the boundary with a consecutive qc accepted", 0, 5, 5, 4, nil, true},
		{"highest vote round zero does not underflow: round 1 accepted", 0, 0, 1, 0, nil, true},
		{"highest vote round zero: round 0 itself still rejected", 0, 0, 0, 0, nil, false},
		{"consecutive qc accept path", 0, 0, 6, 5, nil, true},
		{"consecutive tc accept path", 0, 0, 11, 3, makeTC(10, 1, 2), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newSafetyFixture(1)
			f.safety.highestQCRound = tt.highestQCRound
			f.safety.highestVoteRound = tt.highestVoteRound
			if got := f.safety.safeToTimeout(tt.round, tt.qcRound, tt.tc); got != tt.want {
				t.Errorf("safeToTimeout(%d, %d, tc) = %v, want %v", tt.round, tt.qcRound, got, tt.want)
			}
		})
	}
}

func TestCommitStateIDCandidate(t *testing.T) {
	t.Run("round gap returns zero", func(t *testing.T) {
		f := newSafetyFixture(1)
		qc := bareQC(genesisBlock.GetId(), 0)
		if got := f.safety.commitStateIDCandidate(5, qc); !bytes.Equal(got, zeroHash[:]) {
			t.Errorf("commitStateIDCandidate = %x, want zero", got)
		}
	})

	t.Run("contiguous two-chain returns the parent's pending state", func(t *testing.T) {
		f := newSafetyFixture(1)
		parent := NewBlock(1, 1, [][]byte{[]byte("a")}, GenesisQC())
		state := f.ledger.Speculate(parent)
		qc := bareQC(parent.GetId(), parent.GetRound())
		if got := f.safety.commitStateIDCandidate(2, qc); !bytes.Equal(got, state) {
			t.Errorf("commitStateIDCandidate = %x, want %x", got, state)
		}
	})

	t.Run("no pending state returns zero", func(t *testing.T) {
		f := newSafetyFixture(1)
		qc := bareQC(hashOf(0xAA), 1) // never speculated
		if got := f.safety.commitStateIDCandidate(2, qc); !bytes.Equal(got, zeroHash[:]) {
			t.Errorf("commitStateIDCandidate = %x, want zero", got)
		}
	})
}

func TestMakeVote(t *testing.T) {
	t.Run("nil when the safety rules refuse", func(t *testing.T) {
		f := newSafetyFixture(1)
		f.safety.highestVoteRound = 5 // blocks round 1, which is not > 5
		b := NewBlock(1, 1, nil, GenesisQC())
		f.ledger.Speculate(b)
		if v := f.safety.MakeVote(b, nil); v != nil {
			t.Errorf("MakeVote = %+v, want nil", v)
		}
	})

	t.Run("nil when the ledger never executed the block", func(t *testing.T) {
		f := newSafetyFixture(1)
		b := NewBlock(1, 1, nil, GenesisQC())
		// b is never passed to Speculate, so PendingState(b.GetId()) is false.
		if v := f.safety.MakeVote(b, nil); v != nil {
			t.Errorf("MakeVote = %+v, want nil", v)
		}
	})

	t.Run("success raises both counters and binds the commit info", func(t *testing.T) {
		f := newSafetyFixture(1)

		block1 := NewBlock(1, 1, [][]byte{[]byte("a")}, GenesisQC())
		state1 := f.ledger.Speculate(block1)
		voteInfo1 := diempb.VoteInfo_builder{
			Id: block1.GetId(), Round: 1,
			ParentId: genesisBlock.GetId(), ParentRound: 0,
			ExecStateId: state1,
		}.Build()
		qc1 := makeQC(voteInfo1, nil, 1, 2, 3)

		block2 := NewBlock(1, 2, [][]byte{[]byte("b")}, qc1)
		f.ledger.Speculate(block2)

		vote := f.safety.MakeVote(block2, nil)
		if vote == nil {
			t.Fatal("MakeVote = nil, want a vote")
		}
		if f.safety.highestVoteRound != 2 {
			t.Errorf("HighestVoteRound = %d, want 2", f.safety.highestVoteRound)
		}
		if f.safety.highestQCRound != 1 {
			t.Errorf("HighestQCRound = %d, want 1", f.safety.highestQCRound)
		}
		if !bytes.Equal(vote.GetLedgerCommitInfo().GetVoteInfoHash(), vote.GetVoteInfo().Hash()) {
			t.Error("LedgerCommitInfo.VoteInfoHash does not match vote.VoteInfo.Hash()")
		}
	})
}

func TestMakeTimeout(t *testing.T) {
	t.Run("nil when the safety rules refuse", func(t *testing.T) {
		f := newSafetyFixture(1)
		f.safety.highestQCRound = 10 // GenesisQC's round (0) is now below it
		if to := f.safety.MakeTimeout(1, GenesisQC(), nil); to != nil {
			t.Errorf("MakeTimeout = %+v, want nil", to)
		}
	})

	t.Run("success raises highestVoteRound and signs the timeout digest", func(t *testing.T) {
		f := newSafetyFixture(1)
		to := f.safety.MakeTimeout(1, GenesisQC(), nil)
		if to == nil {
			t.Fatal("MakeTimeout = nil, want a timeout")
		}
		if f.safety.highestVoteRound != 1 {
			t.Errorf("HighestVoteRound = %d, want 1", f.safety.highestVoteRound)
		}
		digest := diempb.TimeoutDigest(to.GetRound(), to.GetHighQc().Round())
		if !verifySig(f.crypto, digest, to.GetSig()) {
			t.Error("timeout signature does not verify against diempb.TimeoutDigest(round, highQC.Round())")
		}
	})
}

// restarted is replica 1 back from a crash: a fresh ledger, and counters
// loaded from what store last saved.
func restarted(store *memStore) *safetyFixture {
	f := newSafetyFixture(1)
	f.safety.set(store.saved)
	f.safety.store = store
	return f
}

// round2 speculates a round-1 block and, over its QC, a round-2 block carrying
// payload. It returns both, so a test can vote on the block or time out on the
// QC.
func round2(f *safetyFixture, payload string) (*diempb.Block, *diempb.QuorumCert) {
	b1 := NewBlock(1, 1, [][]byte{[]byte("a")}, GenesisQC())
	vi := diempb.VoteInfo_builder{
		Id: b1.GetId(), Round: 1,
		ParentId: genesisBlock.GetId(), ParentRound: 0,
		ExecStateId: f.ledger.Speculate(b1),
	}.Build()
	qc1 := makeQC(vi, nil, 1, 2, 3)
	b2 := NewBlock(2, 2, [][]byte{[]byte(payload)}, qc1)
	f.ledger.Speculate(b2)
	return b2, qc1
}

// TestRestartKeepsSafety restarts a replica from its saved counters and checks
// the rules DiemBFT's Lemma 2 rests on still hold. Voting in a round and then
// timing out of it stays allowed, as safe_to_timeout (3.4) permits.
func TestRestartKeepsSafety(t *testing.T) {
	t.Run("no second vote in a round voted in", func(t *testing.T) {
		store := &memStore{}
		f := newSafetyFixture(1)
		f.safety.store = store
		b, _ := round2(f, "b")
		if f.safety.MakeVote(b, nil) == nil {
			t.Fatal("MakeVote = nil, want a vote")
		}
		g := restarted(store)
		other, _ := round2(g, "c")
		if v := g.safety.MakeVote(other, nil); v != nil {
			t.Error("restarted replica voted a second time in round 2")
		}
	})

	t.Run("no vote in a round timed out of", func(t *testing.T) {
		store := &memStore{}
		f := newSafetyFixture(1)
		f.safety.store = store
		_, qc1 := round2(f, "b")
		if f.safety.MakeTimeout(2, qc1, nil) == nil {
			t.Fatal("MakeTimeout = nil, want a timeout")
		}
		g := restarted(store)
		b, _ := round2(g, "b")
		if v := g.safety.MakeVote(b, nil); v != nil {
			t.Error("restarted replica voted in round 2 after timing out of it")
		}
	})

	t.Run("no timeout below the highest QC round voted on", func(t *testing.T) {
		store := &memStore{}
		f := newSafetyFixture(1)
		f.safety.store = store
		b, _ := round2(f, "b")
		if f.safety.MakeVote(b, nil) == nil {
			t.Fatal("MakeVote = nil, want a vote")
		}
		g := restarted(store)
		if to := g.safety.MakeTimeout(1, GenesisQC(), nil); to != nil {
			t.Error("restarted replica timed out reporting a QC below the round-1 QC it voted on")
		}
	})

	t.Run("a failed save signs nothing and the retry saves", func(t *testing.T) {
		store := &memStore{err: errors.New("disk full")}
		f := newSafetyFixture(1)
		f.safety.store = store
		if to := f.safety.MakeTimeout(1, GenesisQC(), nil); to != nil {
			t.Fatal("MakeTimeout signed although the save failed")
		}
		store.err = nil
		if f.safety.MakeTimeout(1, GenesisQC(), nil) == nil {
			t.Fatal("retried MakeTimeout = nil, want a timeout")
		}
		if store.saved.HighestVoteRound != 1 {
			t.Errorf("saved HighestVoteRound = %d, want 1", store.saved.HighestVoteRound)
		}
	})
}
