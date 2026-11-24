package diem

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"slices"
	"sync"

	"github.com/DanyGoT/diembft/proto/diempb"
	"google.golang.org/protobuf/proto"
)

// Verifier authenticates inbound messages. It holds no protocol state — every
// check here is a function of the message and the replica set alone — which is
// what lets it run on the network's handler goroutines, before a message
// reaches the core.
//
// It remembers the QCs whose signatures it has verified, since one QC comes
// back in many later messages: as the high commit QC of every vote, and as a
// timeout's high QC. Two handlers that both miss on one QC both verify it.
//
// It is also the edge that makes a wire message safe to read without checks:
// every hash field of a message it accepts is exactly hashLen bytes, and a
// block's id is the one recomputed from its fields, so no digest from the wire
// is trusted before the Verifier has seen it.
type Verifier struct {
	crypto Crypto
	quorum int

	mu sync.Mutex
	// The keys of QCs whose signatures checked out, in two generations. Once
	// recent is full it becomes older, and the previous older is dropped.
	recent, older map[qcKey]struct{}
}

// verifiedCap bounds a generation of verified QCs. A replica sees about one
// new QC per round, so this spans dozens of rounds.
const verifiedCap = 64

// qcKey identifies a QC by every input of its signature checks.
type qcKey [sha256.Size]byte

// NewVerifier builds a Verifier over the given Crypto and quorum size.
func NewVerifier(crypto Crypto, quorum int) *Verifier {
	return &Verifier{crypto: crypto, quorum: quorum, recent: map[qcKey]struct{}{}}
}

// keyOf hashes what the signature checks of qc read: the digest the quorum
// signed, the signature set, and the author with its signature over the set.
func keyOf(commitDigest, sigsDigest []byte, qc *diempb.QuorumCert) qcKey {
	h := sha256.New()
	h.Write(commitDigest)
	h.Write(sigsDigest)
	h.Write(binary.BigEndian.AppendUint32(nil, qc.GetAuthor()))
	h.Write(qc.GetAuthorSig().GetSig())
	return qcKey(h.Sum(nil))
}

func (v *Verifier) seen(k qcKey) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	_, ok := v.recent[k]
	if !ok {
		_, ok = v.older[k]
	}
	return ok
}

func (v *Verifier) remember(k qcKey) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.recent) == verifiedCap {
		v.older, v.recent = v.recent, make(map[qcKey]struct{}, verifiedCap)
	}
	v.recent[k] = struct{}{}
}

// validHashes reports whether every hash is exactly hashLen bytes.
func validHashes(hs ...[]byte) bool {
	for _, h := range hs {
		if len(h) != hashLen {
			return false
		}
	}
	return true
}

// validVote reports whether the hash fields of a vote's two halves are
// well-sized.
func validVote(v *diempb.VoteInfo, l *diempb.LedgerCommitInfo) bool {
	return validHashes(v.GetId(), v.GetParentId(), v.GetExecStateId(),
		l.GetCommitStateId(), l.GetVoteInfoHash())
}

// VerifyQC reports whether qc carries a quorum over the ledger commit info it
// claims, whether that info binds the VoteInfo it ships with, and whether the
// author it names signed the signature set. Without the second check a
// forwarder could swap in a different VoteInfo behind an otherwise valid
// quorum; without the third, Author is a name a Byzantine aggregator writes
// freely.
func (v *Verifier) VerifyQC(qc *diempb.QuorumCert) bool {
	if qc == nil || !validVote(qc.GetVoteInfo(), qc.GetLedgerCommitInfo()) {
		return false
	}
	if qc.Round() == 0 {
		// Genesis carries neither a quorum nor an author signature, so nothing
		// vouches for a round-0 certificate but equality with the one every
		// replica hardcodes.
		return proto.Equal(qc, genesisQC)
	}
	if !bytes.Equal(qc.GetVoteInfo().Hash(), qc.GetLedgerCommitInfo().GetVoteInfoHash()) {
		return false
	}
	// DiemBFT 3.4 make_vote sets commit_state_id only for a 2-chain. The paper
	// leaves receivers trusting the quorum on that; a commit over a round gap is
	// refused here so a QC alone can never trigger one.
	if vi := qc.GetVoteInfo(); qc.GetLedgerCommitInfo().Commits() && !consecutive(vi.GetRound(), vi.GetParentRound()) {
		return false
	}
	commitDigest, sigsDigest := qc.GetLedgerCommitInfo().Digest(), qc.SigsDigest()
	var b batch
	for _, sig := range qc.GetSignatures() {
		b.add(commitDigest, sig)
	}
	if !v.canonicalSigners(b.signers) || qc.GetAuthorSig().GetSigner() != qc.GetAuthor() {
		return false
	}
	key := keyOf(commitDigest, sigsDigest, qc)
	if v.seen(key) {
		return true
	}
	// The author signature is the paper's author_signature <- sign_u(signatures)
	// (3.3, process_vote). It adds nothing to the quorum's authority; it binds
	// this particular choice of signature set to the replica that chose it,
	// which is what makes an aggregator that hands out two quorums over one vote
	// attributable — the block id covers the set, so the two are different
	// blocks.
	b.add(sigsDigest, qc.GetAuthorSig())
	if !b.verify(v.crypto) {
		return false
	}
	v.remember(key)
	return true
}

// canonicalSigners reports whether a certificate's signers are at least a
// quorum in strictly increasing ID order, so no duplicates and one wire form
// per signer set. Every signature in the set is then verified, so it carries
// no bytes nobody checked. The form matters beyond tidiness here: a block id covers its
// parent certificate's signature slice byte for byte (blockID), so a set left
// unordered or padded with junk is one quorum's worth of distinct block ids.
func (v *Verifier) canonicalSigners(signers []uint32) bool {
	for i := 1; i < len(signers); i++ {
		if signers[i-1] >= signers[i] {
			return false
		}
	}
	return len(signers) >= v.quorum
}

// batch collects a certificate's signatures for one Crypto.VerifyAll call,
// which checks them side by side.
type batch struct {
	signers       []uint32
	digests, sigs [][]byte
}

func (b *batch) add(digest []byte, sig *diempb.Signature) {
	b.signers = append(b.signers, sig.GetSigner())
	b.digests = append(b.digests, digest)
	b.sigs = append(b.sigs, sig.GetSig())
}

func (b *batch) verify(c Crypto) bool { return c.VerifyAll(b.signers, b.digests, b.sigs) }

// VerifyTC reports whether tc carries a quorum of signers in canonical order,
// each having signed tc's round paired with its own reported high_qc round. A
// nil TC is valid: whether one was required is a well-formedness question,
// decided before a message reaches here.
func (v *Verifier) VerifyTC(tc *diempb.TimeoutCert) bool {
	if tc == nil {
		return true
	}
	// Round 0 is genesis, which no replica ever times out of.
	if tc.GetRound() == 0 {
		return false
	}
	var b batch
	for _, vote := range tc.GetVotes() {
		b.add(diempb.TimeoutDigest(tc.GetRound(), vote.GetHighQcRound()), vote.GetSig())
	}
	return v.canonicalSigners(b.signers) && b.verify(v.crypto)
}

// VerifyProposal reports whether p is well formed and validly signed by its
// sender, whether its block carries the id its fields hash to, and whether
// every certificate it carries holds up. Whether its author leads the round is
// checked in Core next to the round check, as DiemBFT v4 3.1
// process_proposal_msg does.
func (v *Verifier) VerifyProposal(p *diempb.ProposalMsg) bool {
	if !p.WellFormed() {
		return false
	}
	b := p.GetBlock()
	// A block must extend a round below its own. The well-formedness rule alone
	// permits any certificate behind a TC, and safeToVote catches the rest only
	// after the pacemaker has advanced and the block has been speculated.
	if b.GetQc().Round() >= b.GetRound() {
		return false
	}
	// The one recomputation of the id; the core reads GetId() from here on.
	if !b.ValidID() {
		return false
	}
	if p.GetSig().GetSigner() != p.GetSender() || !verifySig(v.crypto, b.GetId(), p.GetSig()) {
		return false
	}
	return v.VerifyQC(b.GetQc()) && v.verifyCommitQC(p.GetHighCommitQc(), b.GetQc()) && v.VerifyTC(p.GetLastRoundTc())
}

// VerifyTimeout reports whether m is well formed and validly signed, and
// whether every certificate it carries holds up.
func (v *Verifier) VerifyTimeout(m *diempb.TimeoutMsg) bool {
	if !m.WellFormed() {
		return false
	}
	t := m.GetTmoInfo()
	if t.GetSig().GetSigner() != t.GetSender() ||
		!verifySig(v.crypto, diempb.TimeoutDigest(t.GetRound(), t.GetHighQc().Round()), t.GetSig()) {
		return false
	}
	return v.VerifyQC(t.GetHighQc()) && v.verifyCommitQC(m.GetHighCommitQc(), t.GetHighQc()) && v.VerifyTC(m.GetLastRoundTc())
}

// VerifyVote reports whether m is validly signed by its sender.
func (v *Verifier) VerifyVote(m *diempb.VoteMsg) bool {
	if m.GetSig().GetSigner() != m.GetSender() || !validVote(m.GetVoteInfo(), m.GetLedgerCommitInfo()) {
		return false
	}
	// The vote signs the LedgerCommitInfo alone, so the VoteInfo it ships with
	// is only authenticated through the hash inside it.
	if !bytes.Equal(m.GetVoteInfo().Hash(), m.GetLedgerCommitInfo().GetVoteInfoHash()) {
		return false
	}
	if !verifySig(v.crypto, m.GetLedgerCommitInfo().Digest(), m.GetSig()) {
		return false
	}
	return v.verifyCommitQC(m.GetHighCommitQc(), nil)
}

// verifyCommitQC accepts an absent commit certificate: it is a catch-up hint,
// not evidence anything depends on. It skips one equal to checked, a
// certificate the caller has verified already: when the last QC committed, it
// is also the highest commit QC.
func (v *Verifier) verifyCommitQC(qc, checked *diempb.QuorumCert) bool {
	return qc == nil || proto.Equal(qc, checked) || v.VerifyQC(qc)
}

// VerifyBlock reports whether b is the block with the given id and its QC
// holds up. The id covers the QC's block id and signatures but not the rest of
// it, so only the QC check binds its vote and commit info to the quorum that
// signed.
func (v *Verifier) VerifyBlock(b *diempb.Block, id []byte) bool {
	return bytes.Equal(b.GetId(), id) && b.ValidID() && v.VerifyQC(b.GetQc())
}

// VerifyCommit reports whether proof shows that cmd, an encoded command,
// committed. Every block's id is recomputed, each block is the parent of the
// next, and the first carries cmd. The certificate must commit the last block:
// its vote's parent is that block, at that block's round. VerifyQC then checks
// the quorum's signatures and that the vote's round directly follows its
// parent's, the 2-chain a commit needs (DiemBFT v4 3.4, make_vote). The blocks
// below the last may skip rounds, as they do after a timeout.
func (v *Verifier) VerifyCommit(proof *diempb.CommitProof, cmd []byte) bool {
	blocks := proof.GetBlocks()
	if len(blocks) == 0 || !slices.ContainsFunc(blocks[0].GetPayload(), func(e []byte) bool { return bytes.Equal(e, cmd) }) {
		return false
	}
	for i, b := range blocks {
		if !b.ValidID() || i > 0 && !bytes.Equal(b.ParentID(), blocks[i-1].GetId()) {
			return false
		}
	}
	top, qc := blocks[len(blocks)-1], proof.GetQc()
	vi := qc.GetVoteInfo()
	return qc.GetLedgerCommitInfo().Commits() &&
		bytes.Equal(vi.GetParentId(), top.GetId()) && vi.GetParentRound() == top.GetRound() &&
		v.VerifyQC(qc)
}
