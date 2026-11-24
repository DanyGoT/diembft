// Package replica wires a DiemBFT replica together and owns its lifecycle.
package replica

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/DanyGoT/diembft/diem"
	"github.com/DanyGoT/diembft/diemcrypto"
	"github.com/DanyGoT/diembft/diemnet"
	"github.com/DanyGoT/diembft/proto/diempb"
	"github.com/relab/gorums/benchkit"
)

const (
	defaultRoundTimeout = 100 * time.Millisecond
	defaultBatch        = 64
	defaultPoolSize     = 4096
	defaultStartTimeout = 30 * time.Second

	// submitTimeout bounds how long a client's Submit waits here. A client
	// that gives up does not reach the server, so the wait ends on its own.
	submitTimeout = 10 * time.Second
)

var errStopped = errors.New("replica: stopped")

// ErrStartTimeout is what Run returns when the replicas are not all ready
// within Config.StartTimeout.
var ErrStartTimeout = errors.New("replica: not every replica was ready before the start timeout")

// Config is everything a replica needs.
type Config struct {
	ID uint32
	diemnet.Network

	Key  *ecdsa.PrivateKey
	Keys map[uint32]*ecdsa.PublicKey

	// Batch is the most submitted commands per block, and PoolSize the most
	// submitted and not yet committed. 0 picks a default.
	Batch, PoolSize int

	// OnCommit, if set, runs for every committed block in commit order. It runs
	// under the replica's lock, so it must not block or call into the Replica.
	OnCommit func(*diempb.Block)

	// RoundTimeout is the round timer's α; its β is half of it.
	RoundTimeout time.Duration

	// StartTimeout bounds Run's wait for its peers and for every replica to be
	// ready. 0 picks a default.
	StartTimeout time.Duration

	// Measure configures the measurement taken from core start. Its Duration
	// bounds the run; 0 runs until ctx is done.
	Measure benchkit.Options

	// StateFile, if set, keeps the safety counters across restarts: New loads
	// them from it, and every vote or timeout that raises them saves them there
	// first. Empty keeps them in memory, and a restarted replica can then vote
	// twice in a round.
	StateFile string
}

// Replica is one DiemBFT replica: a protocol core and the Gorums transport
// underneath.
type Replica struct {
	id         uint32
	validators []uint32
	core *diem.Core
	net  *diemnet.Transport

	// mu serializes every call into the core: inbound messages, fetched
	// blocks and the round timer. Gorums runs one sender's handlers in order,
	// and mu serializes them across senders. It also guards commits, commands,
	// the pool and the waiters, which the core reaches through the ledger, the
	// transport and the MemPool.
	mu       sync.Mutex
	commits  []*diempb.Block
	commands uint64
	pool     *pool
	waiters  *waiters
	stopped  bool // Run has returned
	onCommit func(*diempb.Block)

	// proposeToCommit sums the propose-to-commit latency of own blocks.
	proposeToCommit time.Duration
	ownCommits      uint64

	measure      benchkit.Options
	startTimeout time.Duration
	m            *benchkit.Measurement
	result       *benchkit.Result
	started      chan struct{}
}

// New wires a replica. It fails only when StateFile cannot be read or
// written.
func New(cfg Config) (*Replica, error) {
	if cfg.RoundTimeout == 0 {
		cfg.RoundTimeout = defaultRoundTimeout
	}
	if cfg.StartTimeout <= 0 {
		cfg.StartTimeout = defaultStartTimeout
	}
	if cfg.Batch <= 0 {
		cfg.Batch = defaultBatch
	}
	if cfg.PoolSize <= 0 {
		cfg.PoolSize = defaultPoolSize
	}
	// The key set fixes the quorum and the leader rotation, so a peer list that
	// disagrees with it would give this replica a different quorum from its
	// peers. That is a deployment error to fail on, not to reconcile.
	if len(cfg.Peers) != 0 && len(cfg.Peers) != len(cfg.Keys) {
		panic(fmt.Sprintf("replica: %d peer addresses but %d public keys", len(cfg.Peers), len(cfg.Keys)))
	}
	if cfg.Keys[cfg.ID] == nil {
		panic(fmt.Sprintf("replica: no public key registered for this replica's own ID %d", cfg.ID))
	}

	var state diem.SafetyState
	var store diem.SafetyStore
	if cfg.StateFile != "" {
		var fs *fileStore
		var err error
		if state, fs, err = openState(cfg.StateFile); err != nil {
			return nil, err
		}
		// Saving the loaded state back makes a disk that cannot be written fail
		// here rather than silence the replica at its first vote.
		if err := fs.save(state); err != nil {
			return nil, err
		}
		store = fs
	}

	validators := slices.Sorted(maps.Keys(cfg.Keys))
	signer := diemcrypto.New(cfg.Key, cfg.Keys)
	r := &Replica{
		id:           cfg.ID,
		validators:   validators,
		pool:         &pool{batch: cfg.Batch, size: cfg.PoolSize},
		waiters:      newWaiters(cfg.PoolSize),
		onCommit:     cfg.OnCommit,
		measure:      cfg.Measure,
		startTimeout: cfg.StartTimeout,
		started:      make(chan struct{}),
	}
	ledger := diem.NewMemLedger()
	ledger.OnCommit = r.commit

	r.net = diemnet.New(diemnet.Config{
		ID:       cfg.ID,
		Verifier: diem.NewVerifier(signer, diem.QuorumSize(len(validators))),
		Network:  cfg.Network,
		Submit:   r.submit,
	})
	r.core = diem.New(diem.Config{
		ID:         cfg.ID,
		Validators: validators,
		Ledger:     ledger,
		Crypto:     signer,
		Transport:  stamper{r.net, r.pool},
		Clock:      diem.SystemClock{},
		RoundTimer: diem.RoundTimer{Alpha: cfg.RoundTimeout, Beta: cfg.RoundTimeout / 2},
		Lock:       &r.mu,
		MemPool:    r.pool,

		SafetyState: state,
		SafetyStore: store,
	})
	return r, nil
}

// stamper tells the pool when this replica sends each of its proposals.
type stamper struct {
	*diemnet.Transport
	pool *pool
}

func (s stamper) Proposal(p *diempb.ProposalMsg) {
	s.pool.proposed(p.GetBlock().GetRound(), time.Now())
	s.Transport.Proposal(p)
}

// commit appends chain, which qc committed, to the log, oldest first, and
// tells the clients of its commands. For a block this replica proposed, it
// records the propose-to-commit latency and its commands' submit-to-commit
// latency. OnCommit sees every block first, so a client sees its command
// applied. It runs inside a core call, so mu is already held.
func (r *Replica) commit(chain []*diempb.Block, qc *diempb.QuorumCert) {
	for _, b := range chain {
		if own, ok := r.pool.committed(b, r.id); ok {
			r.proposeToCommit += time.Since(own.sent)
			r.ownCommits++
			for _, e := range own.entries {
				r.m.Stats.AddLatency(time.Since(e.submitted))
			}
		}
		r.commits = append(r.commits, b)
		if r.onCommit != nil {
			r.onCommit(b)
		}
	}
	r.commands += r.waiters.committed(chain, qc)
}

// Submit offers cmd for this replica to propose. The Pending closes once cmd
// commits, and the same command submitted again shares it. Submit returns
// false before Started, after Run has returned, when cmd has already
// committed, or when PoolSize commands are already waiting. A Pending still
// open when Run returns never closes.
func (r *Replica) Submit(cmd *diempb.Command) (*Pending, bool) {
	select {
	case <-r.started:
	default:
		return nil, false // Run holds mu until every replica is ready
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	p, err := r.enroll(cmd, true)
	return p, err == nil
}

// submit answers a network client: it waits for cmd to commit and returns the
// proof. Every replica receives every command, and only cmd's owner proposes
// it, so a command is in one block.
func (r *Replica) submit(ctx context.Context, cmd *diempb.Command) (*diempb.CommitProof, error) {
	ctx, cancel := context.WithTimeout(ctx, submitTimeout)
	defer cancel()
	select {
	case <-r.started:
	case <-ctx.Done():
		return nil, ctx.Err() // Run holds mu until every replica is ready
	}
	r.mu.Lock()
	p, err := r.enroll(cmd, r.owner(cmd.GetClient()) == r.id)
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	select {
	case <-p.Done():
		return p.Proof(), nil
	case <-ctx.Done():
		r.mu.Lock()
		r.waiters.drop(cmd, p)
		r.mu.Unlock()
		return nil, ctx.Err()
	}
}

// owner is the replica that proposes client's commands.
func (r *Replica) owner(client uint64) uint32 {
	return r.validators[client%uint64(len(r.validators))]
}

// enroll waits for cmd, and if propose, puts it in the pool the first time.
func (r *Replica) enroll(cmd *diempb.Command, propose bool) (*Pending, error) {
	if r.stopped {
		return nil, errStopped
	}
	p, fresh, err := r.waiters.add(cmd)
	if err != nil || !fresh || !propose {
		return p, err
	}
	if !r.pool.add(cmd.Encode()) {
		r.waiters.drop(cmd, p)
		return nil, errFull
	}
	p.pooled = true
	return p, nil
}

// Run serves the transport, waits for every peer, then for every replica to be
// ready, and runs consensus until ctx is done or Measure.Duration has passed.
// Waiting for peers before the first round matters: a proposal multicast into
// a half-connected configuration is simply lost, and the replicas that missed
// it must fetch it before they can vote again. Waiting for the other replicas
// too keeps a replica whose peers came up early from timing out round 1 alone
// inside its measurement. mu is held until the core has started, so a message
// that arrives earlier waits for it. Cancelling ctx is how a replica stops;
// the transport is shut down before the core.
func (r *Replica) Run(ctx context.Context) error {
	r.mu.Lock()
	r.net.Start(r.core, &r.mu)
	if err := r.start(ctx); err != nil {
		r.mu.Unlock()
		r.net.Stop()
		return err
	}
	r.m = benchkit.StartMeasurement(r.measure)
	r.core.Start()
	r.mu.Unlock()
	close(r.started)

	if d := r.measure.Duration; d > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d)
		defer cancel()
	}
	<-ctx.Done()

	// Gorums does not wait for its handler goroutines on Stop, so a late
	// message can still reach the core, and a stopped core ignores it.
	r.net.Stop()
	r.mu.Lock()
	r.core.Stop()
	r.stopped = true
	r.result = r.m.Finish()
	r.mu.Unlock()
	return ctx.Err()
}

// start waits until this replica's peers are connected and every replica is
// ready, for at most the start timeout, past which it returns ErrStartTimeout.
func (r *Replica) start(ctx context.Context) error {
	ctx, cancel := context.WithTimeoutCause(ctx, r.startTimeout, ErrStartTimeout)
	defer cancel()
	err := r.net.WaitForPeers(ctx)
	if err == nil {
		err = r.net.Barrier(ctx)
	}
	if err != nil && ctx.Err() != nil {
		return context.Cause(ctx)
	}
	return err
}

// Result is the run's measurement: an op is a committed command submitted to
// this replica, timed submit to commit on its own clock. Read it only after Run
// returns; it is nil if Run never reached the first round.
func (r *Replica) Result() *benchkit.Result { return r.result }

// Started is closed when Run reaches the first round, after every replica is
// ready. The measurement and Measure.Duration count from here.
func (r *Replica) Started() <-chan struct{} { return r.started }

// ID is this replica's identity.
func (r *Replica) ID() uint32 { return r.id }

// Log is the committed blocks, in commit order. It is safe to call from any
// goroutine.
func (r *Replica) Log() []*diempb.Block {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*diempb.Block(nil), r.commits...)
}

// ProposeToCommit is the mean time from sending a proposal to committing it,
// over the committed blocks this replica proposed.
func (r *Replica) ProposeToCommit() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ownCommits == 0 {
		return 0
	}
	return r.proposeToCommit / time.Duration(r.ownCommits)
}

// Commands is how many distinct commands the committed blocks carried.
func (r *Replica) Commands() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.commands
}

// Counters is what the transport had to discard.
func (r *Replica) Counters() diemnet.Counters { return r.net.Counters() }

// DeclinedMissingAncestor is how many votes this replica withheld because it
// had not yet seen a block's ancestry. Until it has fetched the missing block,
// a replica that loses one proposal cannot vote on its descendants either; this
// is the number that says what that costs.
func (r *Replica) DeclinedMissingAncestor() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.core.State().DeclinedMissingAncestor
}
