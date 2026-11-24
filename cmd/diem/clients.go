package main

import (
	"context"
	"sync"
	"time"

	"github.com/DanyGoT/diembft/proto/diempb"
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
		id := uint64(r.ID())<<32 | uint64(w)
		wg.Go(func() { client(ctx, r, id, o.std.Payload, limit, pacer) })
	}
	wg.Wait()
}

// client submits one command at a time as client id and waits for it to
// commit. A full pool makes it retry after a short pause.
func client(ctx context.Context, r *replica.Replica, id uint64, size, limit int, pacer *benchkit.Pacer) {
	for seq := uint64(1); limit == 0 || seq <= uint64(limit); seq++ {
		if !pacer.Wait(ctx) {
			return
		}
		cmd := diempb.Command_builder{Client: id, Seq: seq, Payload: make([]byte, size)}.Build()
		p, ok := r.Submit(cmd)
		for !ok {
			select {
			case <-time.After(time.Millisecond):
			case <-ctx.Done():
				return
			}
			p, ok = r.Submit(cmd)
		}
		select {
		case <-p.Done():
		case <-ctx.Done():
			return
		}
	}
}
