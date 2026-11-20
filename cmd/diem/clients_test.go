package main

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestLocalClientsCommitEveryCommandOnce runs -local 4 with 2 workers per
// replica, each sending a fixed number of commands, and checks that every
// client saw each of its commands commit and that every replica committed
// exactly as many commands as were sent.
func TestLocalClientsCommitEveryCommandOnce(t *testing.T) {
	const n, workers, perWorker = 4, 2, 10
	o, _ := parse(t, "-local", "4", "-workers", "2", "-payload", "32", "-time", "0")
	reps, stop, err := o.localCluster(n)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	var runs, clients sync.WaitGroup
	for _, r := range reps {
		runs.Go(func() { _ = r.Run(ctx) })
		clients.Go(func() { o.clients(ctx, r, perWorker) })
	}
	clients.Wait()
	const want = n * workers * perWorker
	for _, r := range reps {
		for r.Commands() < want && ctx.Err() == nil {
			time.Sleep(5 * time.Millisecond)
		}
	}
	if ctx.Err() != nil {
		t.Fatal("timed out before every replica committed every command")
	}
	cancel()
	runs.Wait()

	for _, r := range reps {
		if got := r.Commands(); got != want {
			t.Errorf("replica %d committed %d commands, want %d", r.ID(), got, want)
		}
	}
}
