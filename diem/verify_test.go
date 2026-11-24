package diem

import (
	"slices"
	"testing"

	"github.com/DanyGoT/diembft/diemcrypto"
	"github.com/DanyGoT/diembft/proto/diempb"
	"google.golang.org/protobuf/proto"
)

// The tests here cover the boundary the paper delegates to "other parts of the
// system": everything that is dropped before a message reaches the core. A
// Byzantine replica's whole surface is what it can put on the
// wire, so a message that fails any of these checks must leave no trace.

// newTestVerifier returns the Verifier for the 4-replica group testN and
// testQuorum describe.
func newTestVerifier() *Verifier {
	return NewVerifier(newTestSigner(testN), testQuorum)
}

// TestVerifyRejectsNonCanonicalCertificates pins the canonical signer order on
// inbound certificates. A block id covers its parent certificate's signature
// slice byte for byte (blockID), so a leader that permutes or pads one valid
// quorum mints arbitrarily many distinct, individually valid blocks over the
// same parent — one entry in the pending tree and one speculated state each.
func TestVerifyRejectsNonCanonicalCertificates(t *testing.T) {
	v := newTestVerifier()
	vi := voteInfo(genesisBlock.GetId(), 1, nil, 0)

	t.Run("QC signatures out of signer order", func(t *testing.T) {
		qc := makeQC(vi, nil, 1, 2, 3)
		if !v.VerifyQC(qc) {
			t.Fatal("VerifyQC = false for a canonical quorum, want true")
		}
		slices.Reverse(qc.GetSignatures())
		if v.VerifyQC(qc) {
			t.Error("VerifyQC = true for a permuted signature set, want false")
		}
	})

	t.Run("QC signatures padded with a repeated signer", func(t *testing.T) {
		qc := makeQC(vi, nil, 1, 2, 3)
		qc.SetSignatures(append(qc.GetSignatures(), qc.GetSignatures()[0]))
		if v.VerifyQC(qc) {
			t.Error("VerifyQC = true for a padded signature set, want false")
		}
	})

	// A fourth signer past the quorum: a valid one is a larger quorum, as
	// DiemBFT allows; an invalid one is bytes nobody checked.
	for name, tt := range map[string]struct {
		pad  *diempb.Signature
		want bool
	}{
		"valid":   {signAs(4, commitInfo(nil, vi).Digest()), true},
		"invalid": {diempb.Signature_builder{Signer: 4, Sig: []byte{0xff}}.Build(), false},
	} {
		t.Run("QC signatures padded with a fourth signer, "+name, func(t *testing.T) {
			qc := makeQC(vi, nil, 1, 2, 3)
			qc.SetSignatures(append(qc.GetSignatures(), tt.pad))
			qc.SetAuthorSig(signAs(qc.GetAuthor(), qc.SigsDigest()))
			if got := v.VerifyQC(qc); got != tt.want {
				t.Errorf("VerifyQC = %v, want %v", got, tt.want)
			}
		})
	}

	t.Run("TC votes out of signer order", func(t *testing.T) {
		tc := makeTC(5, 3, 4, 5)
		if !v.VerifyTC(tc) {
			t.Fatal("VerifyTC = false for a canonical quorum, want true")
		}
		slices.Reverse(tc.GetVotes())
		if v.VerifyTC(tc) {
			t.Error("VerifyTC = true for a permuted vote set, want false")
		}
	})
}

// TestVerifyProposalRejectsCertificateAtOrAboveItsOwnRound pins the bound the
// well-formedness rule leaves open on its TC branch: a proposal for round r
// behind a TC for r-1 may carry any QC at all, including one at or above r.
// safeToVote does refuse to vote for it, but only after processCertificateQC
// has dragged the pacemaker to the certificate's round and ExecuteAndInsert has
// speculated and stored the block.
func TestVerifyProposalRejectsCertificateAtOrAboveItsOwnRound(t *testing.T) {
	v := newTestVerifier()
	qc := makeQC(voteInfo(hashOf(0x11), 10, nil, 0), nil, 1, 2, 3)
	b := NewBlock(1, 5, [][]byte{{0xaa}}, qc)
	p := diempb.ProposalMsg_builder{
		Block:       b,
		LastRoundTc: makeTC(4, 1, 2, 3),
		Sender:      1,
		Sig:         signAs(1, b.GetId()),
	}.Build()
	if !p.WellFormed() {
		t.Fatal("setup: the proposal is meant to pass the well-formedness rule")
	}
	if v.VerifyProposal(p) {
		t.Error("VerifyProposal = true for a block whose QC is at round 10 and its own round 5, want false")
	}
}

// countingSigner is a testSigner that counts Verify calls.
type countingSigner struct {
	*testSigner
	verifies, batches int
}

func (s *countingSigner) Verify(signer uint32, digest, sig []byte) bool {
	s.verifies++
	return s.testSigner.Verify(signer, digest, sig)
}

// VerifyAll counts every check: the embedded one would bypass Verify above.
func (s *countingSigner) VerifyAll(signers []uint32, digests, sigs [][]byte) bool {
	s.batches++
	return verifyEach(s.Verify, signers, digests, sigs)
}

// TestVerifyChecksACertificateInOneBatch: a certificate's signatures go to
// Crypto in one call, so it can check them side by side, and a malformed one
// costs no signature check at all.
func TestVerifyChecksACertificateInOneBatch(t *testing.T) {
	vi := voteInfo(hashOf(2), 2, genesisBlock.GetId(), 1)
	outOfOrderTC := makeTC(3, 1, 1, 1)
	votes := outOfOrderTC.GetVotes()
	votes[1], votes[2] = votes[2], votes[1]

	for _, tt := range []struct {
		name              string
		verify            func(*Verifier) bool
		valid             bool
		verifies, batches int
	}{
		{"QC", func(v *Verifier) bool { return v.VerifyQC(makeQC(vi, nil, 1, 2, 3)) }, true, testQuorum + 1, 1},
		{"TC", func(v *Verifier) bool { return v.VerifyTC(makeTC(3, 1, 1, 1)) }, true, testQuorum, 1},
		{"QC out of signer order", func(v *Verifier) bool { return v.VerifyQC(makeQC(vi, nil, 1, 3, 2)) }, false, 0, 0},
		{"QC below a quorum", func(v *Verifier) bool { return v.VerifyQC(makeQC(vi, nil, 1, 2)) }, false, 0, 0},
		{"TC out of signer order", func(v *Verifier) bool { return v.VerifyTC(outOfOrderTC) }, false, 0, 0},
		{"TC below a quorum", func(v *Verifier) bool { return v.VerifyTC(makeTC(3, 1, 1)) }, false, 0, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			crypto := &countingSigner{testSigner: newTestSigner(testN)}
			if got := tt.verify(NewVerifier(crypto, testQuorum)); got != tt.valid {
				t.Fatalf("verification = %v, want %v", got, tt.valid)
			}
			if crypto.verifies != tt.verifies || crypto.batches != tt.batches {
				t.Errorf("made %d signature checks in %d batches, want %d in %d",
					crypto.verifies, crypto.batches, tt.verifies, tt.batches)
			}
		})
	}
}

// TestVerifyChecksSharedCommitQCOnce: when the last QC committed, it is both
// the certificate a message carries and its highest commit QC, and a quorum of
// signatures is the expensive part of verification.
func TestVerifyChecksSharedCommitQCOnce(t *testing.T) {
	qc := makeQC(voteInfo(hashOf(2), 2, genesisBlock.GetId(), 1), hashOf(9), 1, 2, 3)
	commitQC := proto.Clone(qc).(*diempb.QuorumCert)
	b := NewBlock(1, 3, [][]byte{{0xaa}}, qc)
	p := diempb.ProposalMsg_builder{
		Block:        b,
		HighCommitQc: commitQC,
		Sender:       1,
		Sig:          signAs(1, b.GetId()),
	}.Build()
	m := diempb.TimeoutMsg_builder{
		TmoInfo: diempb.TimeoutInfo_builder{
			Round:  3,
			HighQc: qc,
			Sender: 1,
			Sig:    signAs(1, diempb.TimeoutDigest(3, 2)),
		}.Build(),
		HighCommitQc: commitQC,
	}.Build()

	for name, verify := range map[string]func(*Verifier) bool{
		"proposal": func(v *Verifier) bool { return v.VerifyProposal(p) },
		"timeout":  func(v *Verifier) bool { return v.VerifyTimeout(m) },
	} {
		t.Run(name, func(t *testing.T) {
			crypto := &countingSigner{testSigner: newTestSigner(testN)}
			if !verify(NewVerifier(crypto, testQuorum)) {
				t.Fatal("verification = false for a valid message, want true")
			}
			// The message signature, the quorum and the QC's author signature.
			if want := 1 + testQuorum + 1; crypto.verifies != want {
				t.Errorf("made %d signature checks, want %d", crypto.verifies, want)
			}
		})
	}
}

// TestVerifyQCChecksSignaturesOnce: one QC comes back in many later messages,
// and its signatures are the expensive part of checking it.
func TestVerifyQCChecksSignaturesOnce(t *testing.T) {
	qc := makeQC(voteInfo(hashOf(2), 2, genesisBlock.GetId(), 1), hashOf(9), 1, 2, 3)
	crypto := &countingSigner{testSigner: newTestSigner(testN)}
	v := NewVerifier(crypto, testQuorum)
	if !v.VerifyQC(qc) || !v.VerifyQC(proto.Clone(qc).(*diempb.QuorumCert)) {
		t.Fatal("VerifyQC = false for a valid QC, want true")
	}
	// The quorum and the author signature, once.
	if want := testQuorum + 1; crypto.verifies != want {
		t.Errorf("made %d signature checks for one QC seen twice, want %d", crypto.verifies, want)
	}
}

// TestVerifyQCRemembersOnlyWhatItChecked: a QC that differs from a verified
// one in anything its checks read is checked afresh. It signs with real keys,
// because a testSigner signature does not bind its signer.
func TestVerifyQCRemembersOnlyWhatItChecked(t *testing.T) {
	privs, pubs, err := diemcrypto.SeededKeys(testN)
	if err != nil {
		t.Fatal(err)
	}
	signWith := func(id uint32, digest []byte) *diempb.Signature {
		sig, err := sign(diemcrypto.New(privs[id], pubs), id, digest)
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
	qc := makeQCWith(signWith, voteInfo(hashOf(2), 2, genesisBlock.GetId(), 1), hashOf(9), 1, 2, 3)
	v := NewVerifier(diemcrypto.New(nil, pubs), testQuorum)
	if !v.VerifyQC(qc) {
		t.Fatal("VerifyQC = false for a valid QC, want true")
	}

	for name, change := range map[string]func(*diempb.QuorumCert){
		"a quorum signature": func(q *diempb.QuorumCert) {
			q.GetSignatures()[1].SetSig(q.GetSignatures()[0].GetSig())
		},
		"the commit info": func(q *diempb.QuorumCert) { q.GetLedgerCommitInfo().SetCommitStateId(hashOf(8)) },
		"the vote info":   func(q *diempb.QuorumCert) { q.GetVoteInfo().SetExecStateId(hashOf(7)) },
		"the author": func(q *diempb.QuorumCert) {
			q.SetAuthor(2)
			q.GetAuthorSig().SetSigner(2)
		},
		"the author signature": func(q *diempb.QuorumCert) {
			q.GetAuthorSig().SetSig(signWith(2, q.SigsDigest()).GetSig())
		},
	} {
		t.Run(name, func(t *testing.T) {
			q := proto.Clone(qc).(*diempb.QuorumCert)
			change(q)
			if v.VerifyQC(q) {
				t.Error("VerifyQC = true for a QC changed after it was verified, want false")
			}
		})
	}
}

// TestVerifyQCForgetsOldQCs: what the Verifier remembers is bounded.
func TestVerifyQCForgetsOldQCs(t *testing.T) {
	crypto := &countingSigner{testSigner: newTestSigner(testN)}
	v := NewVerifier(crypto, testQuorum)
	qcFor := func(i int) *diempb.QuorumCert {
		return makeQC(voteInfo(hashOf(byte(i), byte(i>>8)), 2, genesisBlock.GetId(), 1), nil, 1, 2, 3)
	}
	for i := range 2*verifiedCap + 1 {
		v.VerifyQC(qcFor(i))
	}
	crypto.verifies = 0
	v.VerifyQC(qcFor(0))
	if crypto.verifies == 0 {
		t.Errorf("the first of %d QCs is still remembered, want it forgotten", 2*verifiedCap+1)
	}
}

// TestVerifyTCRejectsRoundZero covers a guard, not a fix: safeToTimeout
// refuses round 0, so a quorum of round-0 timeouts is unreachable from honest
// replicas and no bug was ever exploitable here. The check is free.
func TestVerifyTCRejectsRoundZero(t *testing.T) {
	if newTestVerifier().VerifyTC(makeTC(0, 1, 2, 3)) {
		t.Error("VerifyTC = true for a TC claiming round 0, want false")
	}
}

func TestVerifyQC(t *testing.T) {
	v := newTestVerifier()

	t.Run("nil is invalid", func(t *testing.T) {
		if v.VerifyQC(nil) {
			t.Error("VerifyQC(nil) = true, want false")
		}
	})

	t.Run("genesis qc is valid", func(t *testing.T) {
		if !v.VerifyQC(GenesisQC()) {
			t.Error("VerifyQC(GenesisQC()) = false, want true")
		}
	})

	t.Run("vote info not bound to the ledger commit info is rejected", func(t *testing.T) {
		vi := voteInfo(genesisBlock.GetId(), 1, nil, 0)
		qc := makeQC(vi, nil, 1, 2, 3)
		qc.GetVoteInfo().SetRound(2) // tamper after the commit hash was computed over Round: 1
		if v.VerifyQC(qc) {
			t.Error("VerifyQC = true for a QC whose VoteInfo does not match its LedgerCommitInfo hash")
		}
	})

	t.Run("commit over a round gap is rejected", func(t *testing.T) {
		vi := voteInfo(hashOf(2), 3, genesisBlock.GetId(), 1)
		if v.VerifyQC(makeQC(vi, hashOf(9), 1, 2, 3)) {
			t.Error("VerifyQC = true for a commit whose block does not directly follow its parent")
		}
		vi = voteInfo(hashOf(2), 2, genesisBlock.GetId(), 1)
		if !v.VerifyQC(makeQC(vi, hashOf(9), 1, 2, 3)) {
			t.Error("VerifyQC = false for a 2-chain commit, want true")
		}
	})

	t.Run("too few signatures is rejected", func(t *testing.T) {
		vi := voteInfo(genesisBlock.GetId(), 1, nil, 0)
		qc := makeQC(vi, nil, 1, 2) // quorum is 3
		if v.VerifyQC(qc) {
			t.Error("VerifyQC = true below quorum, want false")
		}
	})
}

func TestVerifyTC(t *testing.T) {
	v := newTestVerifier()

	t.Run("nil is valid", func(t *testing.T) {
		if !v.VerifyTC(nil) {
			t.Error("VerifyTC(nil) = false, want true")
		}
	})

	t.Run("duplicate signers rejected", func(t *testing.T) {
		tc := tcOf(5,
			tcVote(3, signAs(1, diempb.TimeoutDigest(5, 3))),
			tcVote(3, signAs(1, diempb.TimeoutDigest(5, 3))),
			tcVote(4, signAs(2, diempb.TimeoutDigest(5, 4))))
		if v.VerifyTC(tc) {
			t.Error("VerifyTC = true with a duplicate signer, want false")
		}
	})

	t.Run("wrong-digest signature rejected", func(t *testing.T) {
		tc := tcOf(5,
			tcVote(3, signAs(1, diempb.TimeoutDigest(5, 3))),
			tcVote(4, signAs(2, diempb.TimeoutDigest(99, 4))), // signed a different round
			tcVote(5, signAs(3, diempb.TimeoutDigest(5, 5))))
		if v.VerifyTC(tc) {
			t.Error("VerifyTC = true with a signature over the wrong digest, want false")
		}
	})

	t.Run("below quorum rejected", func(t *testing.T) {
		tc := makeTC(5, 3, 4) // 2 signers, quorum is 3
		if v.VerifyTC(tc) {
			t.Error("VerifyTC = true below quorum, want false")
		}
	})

	t.Run("quorum of distinct signers accepted", func(t *testing.T) {
		tc := makeTC(5, 3, 4, 5)
		if !v.VerifyTC(tc) {
			t.Error("VerifyTC = false for a valid quorum, want true")
		}
	})
}

// TestVerifyProposalRejects is the envelope half of the proposal checks: what a
// receiver can judge from the message and the replica set alone. Whether the
// author leads the round is Core's, and diem/core_test.go holds that case.
func TestVerifyProposalRejects(t *testing.T) {
	v := newTestVerifier()
	tests := []struct {
		name string
		msg  func() *diempb.ProposalMsg
	}{
		{"signature is by someone other than the sender", func() *diempb.ProposalMsg {
			p := proposal(1, 1, 1)
			p.SetSig(signAs(3, p.GetBlock().GetId()))
			return p
		}},
		{"signature covers something other than the block", func() *diempb.ProposalMsg {
			p := proposal(1, 1, 1)
			p.SetSig(signAs(1, hashOf(0xff)))
			return p
		}},
		{"carries a TC its own QC already makes redundant", func() *diempb.ProposalMsg {
			// Well-formedness: a proposal for round r carries the TC of r-1
			// only when its QC is not from r-1. Genesis is from round 0, so
			// any TC here is redundant and the proposal is ill-formed.
			p := proposal(1, 1, 1)
			p.SetLastRoundTc(makeTC(0))
			return p
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if v.VerifyProposal(tt.msg()) {
				t.Error("VerifyProposal = true for a proposal that should have been dropped")
			}
		})
	}
}

// TestVerifyRejectsForgedCertificate pins the check on the certificates a
// message carries, rather than on the message envelope. An unsigned QC that
// claims a high round is the cheapest attack there is: accepting it would drag
// the replica's round and its highest certificate forward on no evidence, and
// no later leader or round check would notice.
func TestVerifyRejectsForgedCertificate(t *testing.T) {
	v := newTestVerifier()
	forged := bareQC(hashOf(0x99), 40)

	t.Run("on a proposal", func(t *testing.T) {
		p := proposal(1, 1, 1)
		p.SetHighCommitQc(forged)
		if v.VerifyProposal(p) {
			t.Error("VerifyProposal = true for a proposal carrying a forged commit certificate")
		}
	})
	t.Run("as a block's parent certificate", func(t *testing.T) {
		b := NewBlock(1, 41, [][]byte{{0xaa}}, forged)
		p := diempb.ProposalMsg_builder{Block: b, HighCommitQc: genesisQC, Sender: 1, Sig: signAs(1, b.GetId())}.Build()
		if v.VerifyProposal(p) {
			t.Error("VerifyProposal = true for a block extending a forged certificate")
		}
	})
	t.Run("on a timeout", func(t *testing.T) {
		m := timeoutFrom(t, 1)
		m.SetHighCommitQc(forged)
		if v.VerifyTimeout(m) {
			t.Error("VerifyTimeout = true for a timeout carrying a forged commit certificate")
		}
	})
	t.Run("on a vote", func(t *testing.T) {
		p := proposal(1, 1, 1)
		vote := voteFor(t, 1, p.GetBlock())
		vote.SetHighCommitQc(forged)
		if v.VerifyVote(vote) {
			t.Error("VerifyVote = true for a vote carrying a forged commit certificate")
		}
	})
}

// forgedGenesisQC is genesisQC with its VoteInfo pointing at parent and its
// commit info claiming a commit: unsigned, yet still round 0 over the genesis id.
func forgedGenesisQC(parent []byte) *diempb.QuorumCert {
	qc := proto.Clone(genesisQC).(*diempb.QuorumCert)
	qc.GetVoteInfo().SetParentId(parent)
	qc.GetLedgerCommitInfo().SetCommitStateId(hashOf(0x09))
	return qc
}

// TestVerifyQCRejectsForgedGenesis pins genesis as one fixed certificate. No
// signature covers a round-0 QC, so one that differs from genesisQC in any
// field is a certificate nobody certified; accepted, its commit info would
// commit whatever parent it names.
func TestVerifyQCRejectsForgedGenesis(t *testing.T) {
	v := newTestVerifier()
	tests := map[string]func(*diempb.QuorumCert){
		"parent id":       func(qc *diempb.QuorumCert) { qc.GetVoteInfo().SetParentId(hashOf(0x01)) },
		"parent round":    func(qc *diempb.QuorumCert) { qc.GetVoteInfo().SetParentRound(7) },
		"commit state id": func(qc *diempb.QuorumCert) { qc.GetLedgerCommitInfo().SetCommitStateId(hashOf(0x09)) },
		"author":          func(qc *diempb.QuorumCert) { qc.SetAuthor(3) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			qc := proto.Clone(genesisQC).(*diempb.QuorumCert)
			mutate(qc)
			if v.VerifyQC(qc) {
				t.Errorf("VerifyQC = true for genesis with a changed %s", name)
			}
		})
	}
	if v.VerifyQC(forgedGenesisQC(hashOf(0x01))) {
		t.Error("VerifyQC = true for a forged genesis certificate that commits")
	}
}

// TestVerifyQCRejectsUnattributedAuthor pins the author signature (3.3,
// process_vote: author <- u, author_signature <- sign_u(signatures)). It
// certifies nothing the quorum does not, so a replica could ignore it and stay
// safe; what it buys is attribution. A QC's signature set is chosen by whoever
// assembled it, and a block id covers that set, so an aggregator that hands out
// two different quorums over one vote is the one thing the quorum signatures
// alone cannot pin on anybody. Unchecked, the field is decoration a Byzantine
// aggregator fills in with any name it likes.
func TestVerifyQCRejectsUnattributedAuthor(t *testing.T) {
	v := newTestVerifier()
	vi := voteInfo(genesisBlock.GetId(), 1, nil, 0)

	if !v.VerifyQC(makeQC(vi, nil, 1, 2, 3)) {
		t.Fatal("VerifyQC = false for a quorum its author signed, want true")
	}
	if !v.VerifyQC(GenesisQC()) {
		t.Fatal("VerifyQC = false for genesis, want true: it is trusted, not certified")
	}

	tamper := map[string]func(*diempb.QuorumCert){
		"no author signature at all": func(qc *diempb.QuorumCert) {
			qc.ClearAuthorSig()
		},
		"author signature by someone other than the named author": func(qc *diempb.QuorumCert) {
			qc.SetAuthor(2)
		},
		"author signature covers a different signature set": func(qc *diempb.QuorumCert) {
			qc.SetAuthorSig(signAs(qc.GetAuthor(), makeQC(vi, nil, 2, 3, 4).SigsDigest()))
		},
	}
	for name, break_ := range tamper {
		t.Run(name, func(t *testing.T) {
			qc := makeQC(vi, nil, 1, 2, 3)
			break_(qc)
			if v.VerifyQC(qc) {
				t.Error("VerifyQC = true for a certificate no author is bound to")
			}
		})
	}
}

func TestVerifyVoteRejects(t *testing.T) {
	v := newTestVerifier()
	tamper := map[string]func(*diempb.VoteMsg){
		"VoteInfo does not match the hash the signature binds": func(m *diempb.VoteMsg) {
			m.GetVoteInfo().SetRound(9)
		},
		"signature is by someone other than the sender": func(m *diempb.VoteMsg) {
			m.SetSender(4)
		},
		"signature covers something other than the ledger commit info": func(m *diempb.VoteMsg) {
			m.SetSig(signAs(m.GetSender(), hashOf(0xff)))
		},
	}
	for name, break_ := range tamper {
		t.Run(name, func(t *testing.T) {
			m := voteFor(t, 1, proposal(1, 1, 1).GetBlock())
			break_(m)
			if v.VerifyVote(m) {
				t.Error("VerifyVote = true for a vote that should have been dropped")
			}
		})
	}
}

func TestVerifyTimeoutRejects(t *testing.T) {
	v := newTestVerifier()
	tamper := map[string]func(*diempb.TimeoutMsg){
		"signature is by someone other than the sender": func(m *diempb.TimeoutMsg) {
			m.GetTmoInfo().SetSender(4)
		},
		"signature covers a different round": func(m *diempb.TimeoutMsg) {
			m.GetTmoInfo().SetSig(signAs(m.GetTmoInfo().GetSender(), diempb.TimeoutDigest(9, 0)))
		},
		"high QC is forged": func(m *diempb.TimeoutMsg) {
			m.GetTmoInfo().SetHighQc(bareQC(hashOf(0x99), 5))
		},
	}
	for name, break_ := range tamper {
		t.Run(name, func(t *testing.T) {
			m := timeoutFrom(t, 1)
			break_(m)
			if v.VerifyTimeout(m) {
				t.Error("VerifyTimeout = true for a timeout that should have been dropped")
			}
		})
	}
}

func tcVote(highQCRound uint64, sig *diempb.Signature) *diempb.TimeoutVote {
	return diempb.TimeoutVote_builder{HighQcRound: highQCRound, Sig: sig}.Build()
}

func tcOf(round uint64, votes ...*diempb.TimeoutVote) *diempb.TimeoutCert {
	return diempb.TimeoutCert_builder{Round: round, Votes: votes}.Build()
}

// TestVerifyRejectsMalformed covers what arrives from a peer that builds its
// messages by hand: absent parts, hashes of the wrong length, a block id that
// is not the digest of its fields. Every hash field of a message the Verifier
// accepts is exactly hashLen bytes, which is what lets the core read them
// without checking.
func TestVerifyRejectsMalformed(t *testing.T) {
	v := newTestVerifier()
	short := []byte{1, 2, 3}

	// A vote whose own fields are broken, re-signed so that only the field
	// under test is wrong.
	reVote := func(vi *diempb.VoteInfo, commit *diempb.LedgerCommitInfo) *diempb.VoteMsg {
		return diempb.VoteMsg_builder{
			VoteInfo: vi, LedgerCommitInfo: commit, Sender: 1,
			Sig: signAs(1, commit.Digest()),
		}.Build()
	}
	good := voteInfo(hashOf(1), 1, genesisBlock.GetId(), 0)
	withInfo := func(mut func(*diempb.VoteInfo)) *diempb.VoteMsg {
		vi := proto.Clone(good).(*diempb.VoteInfo)
		mut(vi)
		return reVote(vi, commitInfo(nil, vi))
	}
	withCommit := func(mut func(*diempb.LedgerCommitInfo)) *diempb.VoteMsg {
		c := commitInfo(nil, good)
		mut(c)
		return reVote(good, c)
	}
	if !v.VerifyVote(reVote(good, commitInfo(nil, good))) {
		t.Fatal("setup: the control vote must verify")
	}

	votes := map[string]*diempb.VoteMsg{
		"nil vote":                   nil,
		"vote without vote info":     reVote(nil, commitInfo(nil, good)),
		"vote without commit info":   reVote(good, nil),
		"vote without a signature":   diempb.VoteMsg_builder{VoteInfo: good, LedgerCommitInfo: commitInfo(nil, good), Sender: 1}.Build(),
		"vote sender 0":              diempb.VoteMsg_builder{VoteInfo: good, LedgerCommitInfo: commitInfo(nil, good), Sig: signAs(0, hashOf())}.Build(),
		"short vote info id":         withInfo(func(vi *diempb.VoteInfo) { vi.SetId(short) }),
		"short vote info parent id":  withInfo(func(vi *diempb.VoteInfo) { vi.SetParentId(short) }),
		"short vote info exec state": withInfo(func(vi *diempb.VoteInfo) { vi.SetExecStateId(short) }),
		"short commit state id":      withCommit(func(c *diempb.LedgerCommitInfo) { c.SetCommitStateId(short) }),
		"short vote info hash":       withCommit(func(c *diempb.LedgerCommitInfo) { c.SetVoteInfoHash(short) }),
		"long commit state id":       withCommit(func(c *diempb.LedgerCommitInfo) { c.SetCommitStateId(append(hashOf(), 0)) }),
	}
	for name, m := range votes {
		t.Run(name, func(t *testing.T) {
			if v.VerifyVote(m) {
				t.Error("VerifyVote = true for a malformed vote")
			}
		})
	}

	t.Run("nil quorum cert", func(t *testing.T) {
		if v.VerifyQC(nil) {
			t.Error("VerifyQC(nil) = true")
		}
	})
	t.Run("quorum cert without vote or commit info", func(t *testing.T) {
		if v.VerifyQC(diempb.QuorumCert_builder{}.Build()) {
			t.Error("VerifyQC = true for an empty certificate")
		}
	})
	t.Run("genesis certificate with a short hash", func(t *testing.T) {
		qc := proto.Clone(GenesisQC()).(*diempb.QuorumCert)
		qc.GetVoteInfo().SetParentId(short)
		if v.VerifyQC(qc) {
			t.Error("VerifyQC = true for genesis with a short parent id")
		}
	})
	t.Run("quorum cert with a short hash", func(t *testing.T) {
		qc := makeQC(voteInfo(genesisBlock.GetId(), 1, nil, 0), nil, 1, 2, 3)
		qc.GetVoteInfo().SetExecStateId(short)
		if v.VerifyQC(qc) {
			t.Error("VerifyQC = true for a certificate with a short exec state id")
		}
	})
	t.Run("quorum cert with a nil signature", func(t *testing.T) {
		qc := makeQC(voteInfo(genesisBlock.GetId(), 1, nil, 0), nil, 1, 2, 3)
		qc.SetSignatures(append(qc.GetSignatures()[:2:2], nil))
		if v.VerifyQC(qc) {
			t.Error("VerifyQC = true with a nil signature in the set")
		}
	})
	t.Run("timeout cert with a nil vote", func(t *testing.T) {
		if v.VerifyTC(tcOf(5, nil, nil, nil)) {
			t.Error("VerifyTC = true for nil votes")
		}
	})

	t.Run("nil proposal", func(t *testing.T) {
		if v.VerifyProposal(nil) {
			t.Error("VerifyProposal(nil) = true")
		}
	})
	t.Run("proposal without a block", func(t *testing.T) {
		if v.VerifyProposal(diempb.ProposalMsg_builder{Sender: 1, Sig: signAs(1, hashOf())}.Build()) {
			t.Error("VerifyProposal = true without a block")
		}
	})
	t.Run("block without a qc", func(t *testing.T) {
		b := diempb.Block_builder{Author: 1, Round: 1}.Build()
		b.SetId(blockID(1, 1, nil, nil))
		p := diempb.ProposalMsg_builder{Block: b, Sender: 1, Sig: signAs(1, b.GetId())}.Build()
		if v.VerifyProposal(p) {
			t.Error("VerifyProposal = true for a block without a qc")
		}
	})
	t.Run("proposal without a signature", func(t *testing.T) {
		p := proposal(1, 1, 1)
		p.ClearSig()
		if v.VerifyProposal(p) {
			t.Error("VerifyProposal = true without a signature")
		}
	})
	t.Run("proposal sender 0", func(t *testing.T) {
		p := proposal(1, 1, 1)
		p.SetSender(0)
		p.SetSig(signAs(0, p.GetBlock().GetId()))
		if v.VerifyProposal(p) {
			t.Error("VerifyProposal = true for sender 0")
		}
	})
	t.Run("proposal with a malformed commit qc", func(t *testing.T) {
		p := proposal(1, 1, 1)
		p.SetHighCommitQc(diempb.QuorumCert_builder{}.Build())
		if v.VerifyProposal(p) {
			t.Error("VerifyProposal = true with an empty commit certificate")
		}
	})

	// The id is a claim like every other digest on the wire: a proposal
	// carrying a different one, correctly signed, must still be dropped.
	t.Run("block id that is not the digest of its fields", func(t *testing.T) {
		p := proposal(1, 1, 1)
		p.GetBlock().SetId(hashOf(0xee))
		p.SetSig(signAs(1, p.GetBlock().GetId()))
		if v.VerifyProposal(p) {
			t.Error("VerifyProposal = true for a block whose id is not recomputed from its fields")
		}
	})
	t.Run("block without an id", func(t *testing.T) {
		p := proposal(1, 1, 1)
		p.GetBlock().SetId(nil)
		if v.VerifyProposal(p) {
			t.Error("VerifyProposal = true for a block with no id")
		}
	})
	t.Run("block id over a tampered payload", func(t *testing.T) {
		p := proposal(1, 1, 1)
		p.GetBlock().SetPayload([][]byte{{0xbb}})
		if v.VerifyProposal(p) {
			t.Error("VerifyProposal = true for a payload the id does not cover")
		}
	})

	t.Run("nil timeout", func(t *testing.T) {
		if v.VerifyTimeout(nil) {
			t.Error("VerifyTimeout(nil) = true")
		}
	})
	t.Run("timeout without tmo info", func(t *testing.T) {
		if v.VerifyTimeout(diempb.TimeoutMsg_builder{}.Build()) {
			t.Error("VerifyTimeout = true without timeout info")
		}
	})
	t.Run("timeout without a high qc", func(t *testing.T) {
		m := timeoutFrom(t, 1)
		m.GetTmoInfo().ClearHighQc()
		if v.VerifyTimeout(m) {
			t.Error("VerifyTimeout = true without a high qc")
		}
	})
	t.Run("timeout without a signature", func(t *testing.T) {
		m := timeoutFrom(t, 1)
		m.GetTmoInfo().ClearSig()
		if v.VerifyTimeout(m) {
			t.Error("VerifyTimeout = true without a signature")
		}
	})
}

// TestVerifyCommit pins every check a client relies on: a proof passes over a
// chain with a round gap, and fails when any single part of it is wrong.
func TestVerifyCommit(t *testing.T) {
	cmd := diempb.Command_builder{Client: 1, Seq: 1, Payload: []byte("x")}.Build().Encode()
	other := diempb.Command_builder{Client: 1, Seq: 2}.Build().Encode()
	b1 := NewBlock(1, 1, [][]byte{other, cmd}, GenesisQC())
	b1QC := makeQC(voteInfo(b1.GetId(), 1, genesisBlock.GetId(), 0), nil, 1, 2, 3)
	b3 := NewBlock(3, 3, nil, b1QC) // round 2 timed out
	commitVote := func(parent []byte, round, parentRound uint64) *diempb.VoteInfo {
		return voteInfo(hashOf(4), round, parent, parentRound)
	}
	valid := func() *diempb.CommitProof {
		return diempb.CommitProof_builder{
			Blocks: []*diempb.Block{b1, b3},
			Qc:     makeQC(commitVote(b3.GetId(), 4, 3), hashOf(9), 1, 2, 3),
		}.Build()
	}
	if !newTestVerifier().VerifyCommit(valid(), cmd) {
		t.Fatal("VerifyCommit = false for a valid proof")
	}

	tests := []struct {
		name   string
		tamper func(p *diempb.CommitProof) []byte // returns the command to look for
	}{
		{"no blocks", func(p *diempb.CommitProof) []byte { p.SetBlocks(nil); return cmd }},
		{"command not in the first block", func(p *diempb.CommitProof) []byte { return []byte("y") }},
		{"command only in a later block", func(p *diempb.CommitProof) []byte {
			p.SetBlocks(p.GetBlocks()[1:])
			return cmd
		}},
		{"block id not recomputed", func(p *diempb.CommitProof) []byte {
			b := proto.CloneOf(b1)
			b.SetPayload([][]byte{cmd})
			p.GetBlocks()[0] = b
			return cmd
		}},
		{"blocks not chained", func(p *diempb.CommitProof) []byte {
			p.GetBlocks()[1] = NewBlock(3, 3, nil, GenesisQC())
			p.SetQc(makeQC(commitVote(p.GetBlocks()[1].GetId(), 4, 3), hashOf(9), 1, 2, 3))
			return cmd
		}},
		{"certificate for another parent", func(p *diempb.CommitProof) []byte {
			p.SetQc(makeQC(commitVote(hashOf(5), 4, 3), hashOf(9), 1, 2, 3))
			return cmd
		}},
		{"certificate for another parent round", func(p *diempb.CommitProof) []byte {
			p.SetQc(makeQC(commitVote(b3.GetId(), 3, 2), hashOf(9), 1, 2, 3))
			return cmd
		}},
		{"certificate commits nothing", func(p *diempb.CommitProof) []byte {
			p.SetQc(makeQC(commitVote(b3.GetId(), 4, 3), nil, 1, 2, 3))
			return cmd
		}},
		{"rounds not consecutive", func(p *diempb.CommitProof) []byte {
			p.SetQc(makeQC(commitVote(b3.GetId(), 5, 3), hashOf(9), 1, 2, 3))
			return cmd
		}},
		{"vote info hash not recomputed", func(p *diempb.CommitProof) []byte {
			p.GetQc().GetVoteInfo().SetExecStateId(hashOf(6))
			return cmd
		}},
		{"too few signers", func(p *diempb.CommitProof) []byte {
			p.SetQc(makeQC(commitVote(b3.GetId(), 4, 3), hashOf(9), 1, 2))
			return cmd
		}},
		{"signer twice", func(p *diempb.CommitProof) []byte {
			p.SetQc(makeQC(commitVote(b3.GetId(), 4, 3), hashOf(9), 1, 2, 2))
			return cmd
		}},
		{"signers out of order", func(p *diempb.CommitProof) []byte {
			p.SetQc(makeQC(commitVote(b3.GetId(), 4, 3), hashOf(9), 2, 1, 3))
			return cmd
		}},
		{"forged signature", func(p *diempb.CommitProof) []byte {
			p.GetQc().GetSignatures()[1].SetSig(hashOf(7))
			return cmd
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := valid()
			want := tt.tamper(p)
			if newTestVerifier().VerifyCommit(p, want) {
				t.Error("VerifyCommit = true, want false")
			}
		})
	}
}
