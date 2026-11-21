package main

import (
	"context"
	"encoding/binary"
	"sync"
	"time"

	"github.com/DanyGoT/diembft/replica"
	"github.com/relab/gorums/benchkit"
)

// idLen is a command's unique prefix: replica, worker and sequence number.
const idLen = 16

// clients runs -workers clients against r from its first round until ctx is
// done, each sending at most limit commands; 0 is no limit.
func (o *options) clients(ctx context.Context, r *replica.Replica, limit int) {
	select {
	case <-r.Started():
	case <-ctx.Done():
		return
	}
	start := time.Now()
	var wg sync.WaitGroup
	for w := range o.std.Workers {
		pacer := benchkit.NewPacer(o.std.Rate, o.std.Workers, w, start)
		wg.Go(func() { client(ctx, r, uint32(w), max(o.std.Payload, idLen), limit, pacer) })
	}
	wg.Wait()
}

// client submits one command at a time and waits for it to commit. A full pool
// makes it retry after a short pause.
func client(ctx context.Context, r *replica.Replica, worker uint32, size, limit int, pacer *benchkit.Pacer) {
	for seq := uint64(0); limit == 0 || seq < uint64(limit); seq++ {
		if !pacer.Wait(ctx) {
			return
		}
		cmd := make([]byte, size)
		binary.BigEndian.PutUint32(cmd, r.ID())
		binary.BigEndian.PutUint32(cmd[4:], worker)
		binary.BigEndian.PutUint64(cmd[8:], seq)
		done, ok := r.Submit(cmd)
		for !ok {
			select {
			case <-time.After(time.Millisecond):
			case <-ctx.Done():
				return
			}
			done, ok = r.Submit(cmd)
		}
		select {
		case <-done:
		case <-ctx.Done():
			return
		}
	}
}
