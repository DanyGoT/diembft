// Command diem runs one DiemBFT replica, or a whole cluster in a single process
// with -local.
//
// The standard flags come from benchkit.RegisterFlags and -output writes a
// benchkit result file, so benchkit/cmd/sweep can drive this binary across a
// cluster. Standard flags with no meaning for one protocol, such as -benchmarks,
// are accepted and ignored.
//
// Each replica runs -workers clients in its own process. A client submits one
// command of -payload bytes and waits for it to commit; together a replica's
// clients send at most -rate commands per second. An op in the result file is
// a committed command, timed submit to commit. -batch caps the commands per
// block. It is not a benchkit dimension, so through sweep it goes in
// -extra-args. With -workers 0 blocks are empty.
//
// -fault-kill-after crashes replica -fault-replica that long after its first
// round, the point -time also counts from, so the wait for peers is not in it.
// Through sweep, pass both in -extra-args, for example
// -extra-args "-insecure-seeded-keys -fault-kill-after=10s -fault-replica=1".
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DanyGoT/diembft/diemcrypto"
	"github.com/DanyGoT/diembft/diemnet"
	"github.com/DanyGoT/diembft/replica"
	"github.com/relab/gorums"
	"github.com/relab/gorums/benchkit"
)

// options holds the parsed command line.
type options struct {
	std *benchkit.StandardFlags

	local          int
	keys           string
	insecureSeeded bool
	genKeys        bool
	viewDuration   time.Duration
	batch          int
	sendBuffer     uint
	recvBuffer     uint
	faultReplica   int
}

// newOptions registers the standard benchkit flags and diem's own on fs.
func newOptions(fs *flag.FlagSet) *options {
	o := &options{std: benchkit.RegisterFlags(fs)}
	fs.IntVar(&o.local, "local", 0, "run this many replicas in one process")
	fs.StringVar(&o.keys, "keys", "", "directory holding <id>.key, <id>.pub and <id>.crt; replicas then talk over mutual TLS; required unless -insecure-seeded-keys")
	fs.BoolVar(&o.insecureSeeded, "insecure-seeded-keys", false, "without -keys, derive every replica's keys from a public seed and talk without TLS; anyone can sign for any replica")
	fs.BoolVar(&o.genKeys, "gen-keys", false, "write a key pair and TLS certificate per replica into -keys and exit")
	fs.IntVar(&o.batch, "batch", 0, "the most commands per block; 0 picks a default")
	fs.DurationVar(&o.viewDuration, "view-duration", 0, "round timer α; it grows by α/2 per round since the last commit; 0 picks a default")
	fs.UintVar(&o.sendBuffer, "send-buffer", 0, "Gorums send queue capacity per peer; 0 picks Gorums' default")
	fs.UintVar(&o.recvBuffer, "recv-buffer", 0, "Gorums receive queue capacity per stream; 0 picks Gorums' default")
	fs.IntVar(&o.faultReplica, "fault-replica", 1, "the replica -fault-kill-after stops, counted from its first round as -time is; every node gets the same sweep -extra-args, so only this one exits")
	return o
}

// faultTarget is the ID of the replica -fault-kill-after stops in an n-replica
// cluster, or 0 when no fault is asked for.
func (o *options) faultTarget(n int) (uint32, error) {
	if o.std.FaultKillAfter <= 0 {
		return 0, nil
	}
	if o.faultReplica < 1 || o.faultReplica > n {
		return 0, fmt.Errorf("-fault-replica %d is not one of the replicas 1..%d", o.faultReplica, n)
	}
	return uint32(o.faultReplica), nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("exiting", "err", err)
		os.Exit(1)
	}
}

func run(args []string) (err error) {
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	o := newOptions(fs)
	_ = fs.Parse(args) // ExitOnError exits on a bad flag
	level := slog.LevelInfo
	if o.std.Verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	stop, err := benchkit.StartProfilers(o.std.CPUProfile, o.std.MemProfile, o.std.Trace)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, stop()) }()

	switch {
	case o.genKeys:
		return o.writeKeys()
	case o.local > 0:
		return o.runLocal(o.local)
	case o.std.Self != "":
		return o.runOne()
	}
	return errors.New("nothing to do: pass -local N, or -self with -remotes")
}

func (o *options) writeKeys() error {
	n := o.local
	if n == 0 {
		addrs, err := o.addresses()
		if err != nil {
			return err
		}
		n = len(addrs)
	}
	if n == 0 || o.keys == "" {
		return errors.New("-gen-keys needs -keys and either -local N or -remotes")
	}
	privs, _, err := diemcrypto.GenerateKeys(n)
	if err != nil {
		return err
	}
	if err := diemcrypto.WriteKeys(o.keys, privs); err != nil {
		return err
	}
	slog.Info("wrote keys", "dir", o.keys, "replicas", n)
	return nil
}

// runLocal runs a whole cluster in one process, over mutual TLS.
// diemnet.LocalServers pre-allocates the loopback listeners and numbers the
// servers 1..n, which is what makes this possible at all: WithPeers needs every
// address before any server exists. Each replica verifies with its own
// Verifier over the public keys, and they share one reject counter.
func (o *options) runLocal(n int) error {
	target, err := o.faultTarget(n)
	if err != nil {
		return err
	}
	reps, stop, err := o.localCluster(n)
	if err != nil {
		return err
	}
	defer stop()
	return o.runAll(n, reps, target)
}

// localCluster builds the n replicas of runLocal; stop shuts their servers.
func (o *options) localCluster(n int) ([]*replica.Replica, func(), error) {
	privs, pubs, err := diemcrypto.GenerateKeys(n)
	if err != nil {
		return nil, nil, err
	}
	certs, err := diemcrypto.Certificates(privs)
	if err != nil {
		return nil, nil, err
	}
	tlsByID := make(map[uint32]*tls.Config, n)
	for id, key := range privs {
		if tlsByID[id], err = diemcrypto.TLSConfig(id, key, certs); err != nil {
			return nil, nil, err
		}
	}
	rejected := new(atomic.Uint64)
	srvs, stop, err := diemnet.LocalServers(n, diemcrypto.New(nil, pubs), rejected, tlsByID, o.serverOptions(), o.dialOptions()...)
	if err != nil {
		return nil, nil, err
	}

	reps := make([]*replica.Replica, n)
	for i := range n {
		id := uint32(i + 1)
		if reps[i], err = replica.New(replica.Config{
			ID: id, Key: privs[id], Keys: pubs,
			Batch:        o.batch,
			RoundTimeout: o.viewDuration,
			Measure:      o.std.Options(),
			Server:       srvs[i],
			Rejected:     rejected,
		}); err != nil {
			stop()
			return nil, nil, err
		}
	}
	return reps, stop, nil
}

// replicaKeys reads id's keys from -keys. Without it, the seeded set every
// replica computes alike is used only when -insecure-seeded-keys asks for it.
func (o *options) replicaKeys(id uint32, n int) (*ecdsa.PrivateKey, map[uint32]*ecdsa.PublicKey, error) {
	if o.keys != "" {
		return diemcrypto.ReadKeys(o.keys, id)
	}
	if !o.insecureSeeded {
		return nil, nil, errors.New("no -keys: pass -keys DIR, or -insecure-seeded-keys to use public-seed keys")
	}
	slog.Warn("using insecure seeded keys")
	privs, pubs, err := diemcrypto.SeededKeys(n)
	if err != nil {
		return nil, nil, err
	}
	return privs[id], pubs, nil
}

// replicaTLS is id's mutual TLS configuration over the certificates of n
// replicas in -keys, or nil, for no transport security, without -keys.
func (o *options) replicaTLS(id uint32, key *ecdsa.PrivateKey, n int) (*tls.Config, error) {
	if o.keys == "" {
		return nil, nil
	}
	certs, err := diemcrypto.ReadCerts(o.keys, n)
	if err != nil {
		return nil, err
	}
	return diemcrypto.TLSConfig(id, key, certs)
}

// runOne runs this process's single replica. -remotes lists every replica in ID
// order, so a replica's position in that list is its ID.
func (o *options) runOne() error {
	addrs, err := o.addresses()
	if err != nil {
		return err
	}
	self := strings.TrimSpace(o.std.Self)
	idx := slices.Index(addrs, self)
	if idx < 0 {
		return fmt.Errorf("-self %q does not appear in -remotes", self)
	}
	id := uint32(idx + 1)
	target, err := o.faultTarget(len(addrs))
	if err != nil {
		return err
	}
	priv, pubs, err := o.replicaKeys(id, len(addrs))
	if err != nil {
		return err
	}
	tlsConfig, err := o.replicaTLS(id, priv, len(pubs))
	if err != nil {
		return err
	}
	peers := make(map[uint32]string, len(addrs))
	for i, addr := range addrs {
		peers[uint32(i+1)] = addr
	}
	r, err := replica.New(replica.Config{
		ID: id, Peers: peers, Listen: self, TLS: tlsConfig,
		Key: priv, Keys: pubs,
		Batch:         o.batch,
		RoundTimeout:  o.viewDuration,
		Measure:       o.std.Options(),
		DialOptions:   o.dialOptions(),
		ServerOptions: o.serverOptions(),
	})
	if err != nil {
		return err
	}
	return o.runAll(len(addrs), []*replica.Replica{r}, target)
}

// runAll runs reps, this process's share of an n-replica cluster, and their
// clients for -time from its first round, or until the process is interrupted,
// then reports what each committed. Replica target, if it is here, stops -fault-kill-after past
// its first round, so neither counts the wait for peers.
// A replica that fails, for example because not every replica was ready within
// the start timeout, stops the others and fails the run, and nothing is
// reported.
func (o *options) runAll(n int, reps []*replica.Replica, target uint32) error {
	root, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	var wg sync.WaitGroup
	var fault *time.Timer
	var mu sync.Mutex
	var failed error
	for _, r := range reps {
		ctx, stop := context.WithCancel(root)
		if r.ID() == target {
			wg.Go(func() {
				select {
				case <-r.Started():
					fault = o.armFault(stop)
				case <-ctx.Done():
				}
			})
		}
		wg.Go(func() { o.clients(ctx, r, 0) })
		wg.Go(func() {
			defer stop()
			if err := r.Run(ctx); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				mu.Lock()
				failed = errors.Join(failed, fmt.Errorf("replica %d: %w", r.ID(), err))
				mu.Unlock()
				cancel()
			}
		})
	}
	wg.Wait()
	if fault != nil {
		fault.Stop()
	}
	if failed != nil {
		return failed
	}
	sums := make([]summary, len(reps))
	results := make([]*benchkit.Result, len(reps))
	for i, r := range reps {
		sums[i], results[i] = summarize(r), r.Result()
	}
	if err := report(os.Stderr, sums); err != nil {
		return err
	}
	if o.std.Output == "" {
		return nil
	}
	return o.writeResults(n, results)
}

// armFault stops the fault target -fault-kill-after from now. With -local the
// target's run is cancelled and it still reports. On the cluster the process
// exits and writes no result, which sweep reads as a crashed node.
func (o *options) armFault(stop context.CancelFunc) *time.Timer {
	if o.local > 0 {
		return time.AfterFunc(o.std.FaultKillAfter, stop)
	}
	return benchkit.ArmFaultInjection(o.std.FaultKillAfter)
}

// addresses is -remotes as a list, whitespace trimmed. A replica's position in
// it is its ID, so an empty or repeated entry would hand two replicas the same
// identity rather than fail.
func (o *options) addresses() ([]string, error) {
	if len(o.std.Remotes) == 1 && strings.TrimSpace(o.std.Remotes[0]) == "" {
		return nil, nil
	}
	addrs := make([]string, len(o.std.Remotes))
	seen := make(map[string]bool, len(addrs))
	for i, addr := range o.std.Remotes {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			return nil, fmt.Errorf("-remotes entry %d is empty", i+1)
		}
		if seen[addr] {
			return nil, fmt.Errorf("-remotes lists %q twice; each entry is one replica's ID", addr)
		}
		seen[addr] = true
		addrs[i] = addr
	}
	return addrs, nil
}

func (o *options) dialOptions() []gorums.DialOption {
	return []gorums.DialOption{gorums.WithDialBufferSizes(o.recvBuffer, o.sendBuffer)}
}

func (o *options) serverOptions() []gorums.ServerOption {
	return []gorums.ServerOption{gorums.WithBufferSizes(o.recvBuffer, o.sendBuffer)}
}
