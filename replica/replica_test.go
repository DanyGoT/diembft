package replica

import (
	"bytes"
	"context"
	"errors"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DanyGoT/diembft/diem"
	"github.com/DanyGoT/diembft/diemcrypto"
	"github.com/DanyGoT/diembft/diemnet"
	"github.com/DanyGoT/diembft/proto/diempb"
	"github.com/relab/gorums"
	"github.com/relab/gorums/benchkit"
	"google.golang.org/grpc"
)

const testRound = 20 * time.Millisecond

// waitFor polls pred until it holds or timeout passes, so no test needs a
// sleep to synchronise on a condition.
func waitFor(timeout time.Duration, pred func() bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		if pred() {
			return true
		}
		if time.Now().After(deadline) {
			return pred()
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// cluster builds n replicas on one process's Gorums local servers, adding dial
// to their dial options, and returns them with a func that runs them under ctx
// and blocks until every Run has returned.
func cluster(t *testing.T, n int, round time.Duration, dial ...gorums.DialOption) ([]*Replica, func(context.Context)) {
	t.Helper()

	privs, pubs, err := diemcrypto.GenerateKeys(n)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	rejected := new(atomic.Uint64)
	verifier := diem.NewVerifier(diemcrypto.New(nil, pubs), diem.QuorumSize(n))
	srvs, stopSrvs, err := diemnet.LocalServers(n, verifier, rejected, nil, dial...)
	if err != nil {
		t.Fatalf("LocalServers: %v", err)
	}
	t.Cleanup(stopSrvs)

	reps := make([]*Replica, n)
	for i := range n {
		id := uint32(i + 1)
		reps[i] = New(Config{
			ID:           id,
			Key:          privs[id],
			Keys:         pubs,
			MemPool:      NewPayload(32, 4, 0),
			RoundTimeout: round,
			Measure:      benchkit.Options{Interval: round},
			Server:       srvs[i],
			Rejected:     rejected,
		})
	}

	run := func(ctx context.Context) {
		var wg sync.WaitGroup
		for _, r := range reps {
			wg.Go(func() {
				if err := r.Run(ctx); !errors.Is(err, context.Canceled) {
					t.Errorf("replica %d: Run returned %v, want context.Canceled", r.ID(), err)
				}
			})
		}
		wg.Wait()
	}
	return reps, run
}

func depths(reps []*Replica) []int {
	d := make([]int, len(reps))
	for i, r := range reps {
		d[i] = len(r.Log())
	}
	return d
}

// TestClusterCommitsIdenticalPrefix runs four replicas over real
// Gorums and checks they commit an agreeing, genesis-rooted chain with nothing
// dropped or rejected on the happy path. Every block id on the receiving side
// was recomputed from the wire form, so an agreeing chain is also the proof
// that the wire round trip is faithful.
func TestClusterCommitsIdenticalPrefix(t *testing.T) {
	const n = 4
	reps, run := cluster(t, n, testRound)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	allDone := make(chan struct{})
	go func() { run(ctx); close(allDone) }()

	const wantDepth = 20
	if !waitFor(10*time.Second, func() bool {
		for _, r := range reps {
			if len(r.Log()) < wantDepth {
				return false
			}
		}
		return true
	}) {
		t.Fatalf("depths after timeout: %v, want every replica >= %d", depths(reps), wantDepth)
	}

	logs := make([][]*diempb.Block, n)
	for i, r := range reps {
		logs[i] = r.Log()
	}
	for i := range logs {
		for j := i + 1; j < n; j++ {
			for k := range min(len(logs[i]), len(logs[j])) {
				if !bytes.Equal(logs[i][k].GetId(), logs[j][k].GetId()) {
					t.Fatalf("replicas %d and %d disagree at commit %d: round %d against round %d",
						i+1, j+1, k, logs[i][k].GetRound(), logs[j][k].GetRound())
				}
			}
		}
	}
	for i, log := range logs {
		if !bytes.Equal(log[0].ParentID(), diem.GenesisQC().BlockID()) {
			t.Errorf("replica %d: the first commit does not extend genesis", i+1)
		}
		for k := 1; k < len(log); k++ {
			if !bytes.Equal(log[k].ParentID(), log[k-1].GetId()) {
				t.Errorf("replica %d: commit %d does not extend commit %d", i+1, k, k-1)
			}
			if log[k].GetRound() <= log[k-1].GetRound() {
				t.Errorf("replica %d: commit rounds not increasing: %d then %d", i+1, log[k-1].GetRound(), log[k].GetRound())
			}
		}
	}

	for _, r := range reps {
		c := r.Counters()
		if c.OutboundDropped != 0 || c.Rejected != 0 {
			// Either would mean the harness misconfigured a replica (a missing
			// peer or a bad key), not a protocol-level fault.
			t.Errorf("replica %d: Counters = %+v, want zero OutboundDropped and Rejected", r.ID(), c)
		}
		// Not an assertion: a replica that misses a proposal declines to vote
		// on its descendants until it has fetched it, and the rate is what the
		// report quotes about that gap.
		t.Logf("replica %d: committed %d, declined for a missing ancestor %d",
			r.ID(), len(r.Log()), r.DeclinedMissingAncestor())
	}

	cancel()
	<-allDone
}

// TestResultCountsOwnBlocks pins that a replica's result counts only the
// committed blocks it proposed, so the replicas' throughputs sum to the system
// rate rather than n times it, and that the interval stream covers every op.
func TestResultCountsOwnBlocks(t *testing.T) {
	reps, run := cluster(t, 4, testRound)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	allDone := make(chan struct{})
	go func() { run(ctx); close(allDone) }()

	const wantDepth = 20
	if !waitFor(10*time.Second, func() bool { return slices.Min(depths(reps)) >= wantDepth }) {
		t.Fatalf("depths after timeout: %v, want every replica >= %d", depths(reps), wantDepth)
	}
	cancel()
	<-allDone

	for _, r := range reps {
		var own uint64
		for _, b := range r.Log() {
			if b.GetAuthor() == r.ID() {
				own++
			}
		}
		res := r.Result()
		if got := res.GetTotalOps(); got != own {
			t.Errorf("replica %d: TotalOps = %d, want %d own blocks of %d committed", r.ID(), got, own, len(r.Log()))
		}
		var streamed uint64
		for _, e := range res.GetEvents() {
			streamed += e.GetThroughput().GetOps()
		}
		if streamed != own {
			t.Errorf("replica %d: interval events carry %d ops, want %d", r.ID(), streamed, own)
		}
	}
}

// TestStartedWaitsForPeers pins that Started, which cmd/diem counts
// -fault-kill-after from, closes only once every peer is connected: not while
// one is down, and once the whole cluster is up.
func TestStartedWaitsForPeers(t *testing.T) {
	privs, pubs, err := diemcrypto.GenerateKeys(2)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	down, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := down.Close(); err != nil {
		t.Fatal(err)
	}
	lone := New(Config{
		ID: 1, Key: privs[1], Keys: pubs,
		Listen: "127.0.0.1:0",
		Peers:  map[uint32]string{1: "127.0.0.1:0", 2: down.Addr().String()},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := lone.Run(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run with a peer down returned %v, want context.DeadlineExceeded", err)
	}
	select {
	case <-lone.Started():
		t.Fatal("Started closed while a peer was down")
	default:
	}

	reps, run := cluster(t, 4, testRound)
	ctx, cancel = context.WithCancel(context.Background())
	t.Cleanup(cancel)
	allDone := make(chan struct{})
	go func() { run(ctx); close(allDone) }()
	for _, r := range reps {
		select {
		case <-r.Started():
		case <-time.After(10 * time.Second):
			t.Fatalf("replica %d: Started not closed with every peer up", r.ID())
		}
	}
	cancel()
	<-allDone
}

// stallStreams makes every stream stop sending, as it does when the peer stops
// reading, until the stream closes.
var stallStreams = gorums.WithGRPCDialOptions(grpc.WithStreamInterceptor(
	func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		cs, err := streamer(ctx, desc, cc, method, opts...)
		if err != nil {
			return nil, err
		}
		return stalled{cs}, nil
	}))

type stalled struct{ grpc.ClientStream }

func (s stalled) SendMsg(any) error {
	<-s.Context().Done()
	return s.Context().Err()
}

// TestStalledPeersDropInsteadOfBlocking stalls every stream behind a one-slot
// send queue. Each replica's round timer must keep firing, so its sends fill
// the queues and are counted as drops instead of blocking the core with mu
// held, and cancelling must still stop every replica.
func TestStalledPeersDropInsteadOfBlocking(t *testing.T) {
	reps, run := cluster(t, 4, testRound, gorums.WithDialBufferSizes(0, 1), stallStreams)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	allDone := make(chan struct{})
	go func() { run(ctx); close(allDone) }()

	dropping := func() bool {
		for _, r := range reps {
			if r.Counters().OutboundDropped == 0 {
				return false
			}
		}
		return true
	}
	if !waitFor(10*time.Second, dropping) {
		for _, r := range reps {
			if r.Counters().OutboundDropped == 0 {
				t.Errorf("replica %d: OutboundDropped = 0, want > 0", r.ID())
			}
		}
	}
	cancel()
	select {
	case <-allDone:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return with every stream stalled")
	}
}

// TestNewRejectsMismatchedPeersAndKeys: the public keys are the replica set, so
// a peer list of a different size would give this replica a quorum its peers
// do not share.
func TestNewRejectsMismatchedPeersAndKeys(t *testing.T) {
	privs, pubs, err := diemcrypto.GenerateKeys(4)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}
	cfg := func() Config {
		return Config{ID: 1, Key: privs[1], Keys: pubs, Listen: "127.0.0.1:0"}
	}

	t.Run("too few peers", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Error("New accepted 3 peer addresses against 4 public keys")
			}
		}()
		c := cfg()
		c.Peers = map[uint32]string{1: "a:1", 2: "b:2", 3: "c:3"}
		New(c)
	})

	t.Run("own key missing", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Error("New accepted a key set with no key for this replica's own ID")
			}
		}()
		c := cfg()
		c.ID = 9
		New(c)
	})
}
