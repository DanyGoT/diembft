package diem

import "testing"

func TestGetLeaderRoundRobinTwoRoundsEachRegardlessOfOrder(t *testing.T) {
	leA := NewLeaderElection([]uint32{1, 2, 3, 4})
	leB := NewLeaderElection([]uint32{4, 3, 2, 1})

	want := []uint32{1, 1, 2, 2, 3, 3, 4, 4, 1, 1}
	for r, id := range want {
		if got := leA.GetLeader(uint64(r)); got != id {
			t.Errorf("orderA: GetLeader(%d) = %d, want %d", r, got, id)
		}
		if got := leB.GetLeader(uint64(r)); got != id {
			t.Errorf("orderB: GetLeader(%d) = %d, want %d", r, got, id)
		}
	}
}
