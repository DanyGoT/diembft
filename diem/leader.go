package diem

import "slices"

// LeaderElection is the paper's LeaderElection module (3.7), round-robin only.
//
// DiemBFT v4 3.7 update_leaders elects a reputation leader for round r+2 only
// when the QC for round r arrives while this replica is in round r+1, and
// get_leader falls back to round-robin otherwise. Whether a replica sees that
// QC in time depends on message order, so replicas can disagree on the leader
// and the round can end in a timeout. Here the leader is a function of the round
// alone, so every replica agrees.
type LeaderElection struct {
	validators []uint32
}

// NewLeaderElection returns the leader election for a replica set. validators
// is sorted, so every replica indexes the same rotation.
func NewLeaderElection(validators []uint32) *LeaderElection {
	v := slices.Clone(validators)
	slices.Sort(v)
	return &LeaderElection{validators: v}
}

// GetLeader names the leader of round. Each validator leads two consecutive
// rounds. That is what makes the pipeline's happy path work without a
// handover: the leader of round r+1 collects the votes for round r, and half
// the time it is the same replica.
func (e *LeaderElection) GetLeader(round uint64) uint32 {
	return e.validators[(round/2)%uint64(len(e.validators))]
}
