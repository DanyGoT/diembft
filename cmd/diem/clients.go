package main

import (
	"context"
	"sync"
	"time"

	"github.com/DanyGoT/diembft/replica"
	"github.com/relab/gorums/benchkit"
)

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
		wg.Go(func() { client(ctx, r, o.std.Payload, limit, pacer) })
	}
	wg.Wait()
}

// client submits one command at a time and waits for it to commit. A full pool
// makes it retry after a short pause.
func client(ctx context.Context, r *replica.Replica, size, limit int, pacer *benchkit.Pacer) {
	for sent := 0; limit == 0 || sent < limit; sent++ {
		if !pacer.Wait(ctx) {
			return
		}
		cmd := make([]byte, size)
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
