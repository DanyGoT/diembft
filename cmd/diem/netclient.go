package main

import (
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/DanyGoT/diembft/diem"
	"github.com/DanyGoT/diembft/diemcrypto"
	"github.com/DanyGoT/diembft/diemnet"
	"github.com/DanyGoT/diembft/proto/diempb"
	"github.com/relab/gorums/benchkit"
)

// defaultCallTimeout bounds one call without -call-timeout. A command that has
// not committed by then is a failed op, and the client moves on to its next.
const defaultCallTimeout = 10 * time.Second

// failPause is how long a client waits after a failed call. A call fails at
// once while its connections are down, and a client that retried at once
// would spin through thousands of failed ops.
const failPause = 100 * time.Millisecond

// runClient runs -workers network clients against the replicas in -remotes
// for -time once every replica answers, or until interrupted, and reports
// their submit-to-commit latency, timed until the proof has been checked.
// With -ping, an op is an empty call.
func (o *options) runClient() error {
	addrs, err := o.addresses()
	if err != nil {
		return err
	}
	if len(addrs) == 0 {
		return errors.New("-client needs -remotes")
	}
	pubs, tlsConfig, err := o.clientKeys(len(addrs))
	if err != nil {
		return err
	}
	peers := make(map[uint32]string, len(addrs))
	for i, addr := range addrs {
		peers[uint32(i+1)] = addr
	}
	ver := diem.NewVerifier(diemcrypto.New(nil, pubs), diem.QuorumSize(len(addrs)))
	c, err := diemnet.Dial(peers, tlsConfig, ver, o.dialOptions()...)
	if err != nil {
		return err
	}
	defer c.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	if err := c.Ready(ctx); err != nil {
		return err
	}
	if d := o.std.Duration; d > 0 {
		ctx, cancel = context.WithTimeout(ctx, d)
		defer cancel()
	}
	base, err := clientBase()
	if err != nil {
		return err
	}
	m := benchkit.StartMeasurement(o.std.Options())
	start := time.Now()
	var wg sync.WaitGroup
	for w := range o.std.Workers {
		pacer := benchkit.NewPacer(o.std.Rate, o.std.Workers, w, start)
		id := base + uint64(w)
		wg.Go(func() { o.netClient(ctx, c, m, id, pacer) })
	}
	wg.Wait()
	res := m.Finish()
	_, _ = fmt.Fprintf(os.Stderr, "client: %d ops, %d failed\n", res.GetTotalOps(), res.GetFailedOps())
	if o.std.Output == "" {
		return nil
	}
	return o.writeResults(len(addrs), []*benchkit.Result{res})
}

// netClient is one client, id, with one call in flight.
func (o *options) netClient(ctx context.Context, c *diemnet.Client, m *benchkit.Measurement, id uint64, pacer *benchkit.Pacer) {
	timeout := cmp.Or(o.std.CallTimeout, defaultCallTimeout)
	for seq := uint64(1); pacer.Wait(ctx); seq++ {
		cctx, cancel := context.WithTimeout(ctx, timeout)
		start := time.Now()
		var err error
		if o.ping {
			err = c.Ping(cctx)
		} else {
			cmd := diempb.Command_builder{Client: id, Seq: seq, Payload: make([]byte, o.std.Payload)}.Build()
			_, err = c.Submit(cctx, cmd)
		}
		cancel()
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			slog.Debug("call failed", "client", id, "seq", seq, "err", err)
			m.RecordError()
			select {
			case <-ctx.Done():
				return
			case <-time.After(failPause):
			}
		default:
			m.Stats.AddLatency(time.Since(start))
		}
	}
}

// clientBase is a random first client id. A replica drops a client's commands
// at or below the last it committed, so ids must not repeat across runs
// against the same replicas. Consecutive ids spread over the owners evenly.
func clientBase() (uint64, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b[:]), nil
}

// clientKeys is the replicas' public keys and the client's TLS configuration,
// from -keys, which needs no private key, or the seeded set without TLS.
func (o *options) clientKeys(n int) (map[uint32]*ecdsa.PublicKey, *tls.Config, error) {
	if o.keys == "" {
		if !o.insecureSeeded {
			return nil, nil, errors.New("no -keys: pass -keys DIR, or -insecure-seeded-keys to use public-seed keys")
		}
		_, pubs, err := diemcrypto.SeededKeys(n)
		return pubs, nil, err
	}
	pubs, err := diemcrypto.ReadPublicKeys(o.keys)
	if err != nil {
		return nil, nil, err
	}
	if len(pubs) != n {
		return nil, nil, fmt.Errorf("%s holds %d public keys but -remotes lists %d replicas", o.keys, len(pubs), n)
	}
	certs, err := diemcrypto.ReadCerts(o.keys, n)
	if err != nil {
		return nil, nil, err
	}
	tlsConfig, err := diemcrypto.ClientTLSConfig(certs)
	return pubs, tlsConfig, err
}
