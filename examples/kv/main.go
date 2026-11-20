// Command kv is a key-value store replicated by one DiemBFT replica per
// process, with HTTP as the client interface:
//
//	curl -X PUT -d world http://host:8080/kv/hello
//	curl http://host:8080/kv/hello
//
// A PUT goes through consensus and returns once its replica has committed it.
// A GET reads this replica's copy. GET / is a page that shows every replica.
// It is a demo: keys are derived from a public seed and the replicas talk
// without TLS, so run it on a network that is private already.
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DanyGoT/diembft/diemcrypto"
	"github.com/DanyGoT/diembft/proto/diempb"
	"github.com/DanyGoT/diembft/replica"
	"github.com/relab/gorums/benchkit"
)

//go:embed index.html
var page []byte

const (
	commitWait = 10 * time.Second
	recentLen  = 20
	interval   = time.Second // of the result file's event stream

	// maxCommand keeps a full block of commands well inside gRPC's 4 MiB
	// message limit; a proposal over it would be dropped by every peer.
	maxCommand = 8 << 10
)

func main() {
	if err := run(); err != nil {
		slog.Error("exiting", "err", err)
		os.Exit(1)
	}
}

func run() error {
	// Termux starts a binary through Android's linker, which passes the
	// binary's path once more as the first argument. Flag parsing would stop
	// there and ignore every flag after it.
	if a := os.Args; runtime.GOOS == "android" && len(a) > 1 && filepath.Base(a[1]) == filepath.Base(a[0]) {
		os.Args = slices.Delete(a, 1, 2)
	}
	self := flag.String("self", "", "this replica's consensus address; must appear in -remotes")
	remotes := flag.String("remotes", "", "every replica's consensus address, comma-separated, in ID order")
	web := flag.String("http", "", "every replica's HTTP address, comma-separated, in the order of -remotes")
	names := flag.String("names", "", "every replica's name for the page, comma-separated, in the order of -remotes; default the HTTP addresses")
	dur := flag.Duration("time", 0, "how long to run; 0 runs until interrupted")
	output := flag.String("output", "", "write a benchkit result file here on exit")
	flag.Parse()

	addrs, webs, labels := split(*remotes), split(*web), split(*names)
	if labels == nil {
		labels = webs
	}
	id := slices.Index(addrs, *self) + 1
	switch {
	case id == 0:
		return fmt.Errorf("-self %q does not appear in -remotes", *self)
	case len(webs) != len(addrs):
		return fmt.Errorf("-http lists %d addresses, -remotes %d", len(webs), len(addrs))
	case len(labels) != len(addrs):
		return fmt.Errorf("-names lists %d names, -remotes %d", len(labels), len(addrs))
	}
	privs, pubs, err := diemcrypto.SeededKeys(len(addrs))
	if err != nil {
		return err
	}
	peers := make(map[uint32]string, len(addrs))
	for i, a := range addrs {
		peers[uint32(i+1)] = a
	}

	s := &server{id: uint32(id), kv: map[string]string{}}
	for i := range webs {
		s.peers = append(s.peers, peer{Name: labels[i], Addr: webs[i]})
	}
	s.r = replica.New(replica.Config{
		ID:    uint32(id),
		Peers: peers, Listen: *self,
		Key:      privs[uint32(id)],
		Keys:     pubs,
		OnCommit: s.apply,
		Measure:  benchkit.Options{Duration: *dur, Interval: interval},
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	srv := &http.Server{Addr: webs[id-1], Handler: s.routes()}
	httpErr := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			httpErr <- err
			stop()
		}
	}()
	go func() {
		select {
		case <-s.r.Started():
			now := time.Now()
			s.start.Store(&now)
		case <-ctx.Done():
		}
	}()
	slog.Info("serving", "id", id, "page", "http://"+webs[id-1]+"/")

	err = s.r.Run(ctx)
	_ = srv.Close()
	select {
	case err := <-httpErr:
		return err
	default:
	}
	if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if res := s.r.Result(); *output != "" && res != nil {
		cfg := res.GetConfig()
		cfg.ApplyDimensions(benchkit.Dimensions{Benchmark: "kv", Nodes: len(addrs)})
		cfg.SetDuration(int64(*dur))
		cfg.SetInterval(int64(interval))
		return benchkit.WriteLabeledReport([]*benchkit.Result{res}, *self, *output)
	}
	return nil
}

func split(list string) []string {
	var out []string
	for a := range strings.SplitSeq(list, ",") {
		if a = strings.TrimSpace(a); a != "" {
			out = append(out, a)
		}
	}
	return out
}

// peer is a replica as the page shows it.
type peer struct {
	Name string `json:"name"`
	Addr string `json:"addr"`
}

// command is what a PUT submits. ID makes it unique, so two PUTs of the same
// pair are two commands.
type command struct {
	ID    string `json:"id"`
	Key   string `json:"k"`
	Value string `json:"v"`
}

type server struct {
	id    uint32
	peers []peer
	r     *replica.Replica
	seq   atomic.Uint64
	start atomic.Pointer[time.Time] // when the replica reached its first round

	// mu guards the state OnCommit applies. apply runs under the replica's
	// lock, so a handler must never call into the replica while holding mu.
	mu     sync.Mutex
	kv     map[string]string
	recent []string // the last committed commands, newest first
}

// apply executes a committed block.
func (s *server) apply(b *diempb.Block) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, raw := range b.GetPayload() {
		var c command
		if json.Unmarshal(raw, &c) != nil {
			continue
		}
		s.kv[c.Key] = c.Value
		s.recent = slices.Insert(s.recent, 0, fmt.Sprintf("%d: %s=%s", b.GetRound(), c.Key, c.Value))
		s.recent = s.recent[:min(len(s.recent), recentLen)]
	}
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(page)
	})
	mux.HandleFunc("PUT /kv/{key}", s.put)
	mux.HandleFunc("GET /kv/{key}", s.get)
	mux.HandleFunc("GET /kv", s.all)
	mux.HandleFunc("GET /metrics", s.metrics)
	mux.HandleFunc("GET /peers", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, s.peers) })
	return mux
}

func (s *server) put(w http.ResponseWriter, req *http.Request) {
	value, err := io.ReadAll(io.LimitReader(req.Body, maxCommand+1))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c := command{ID: fmt.Sprintf("%d-%d", s.id, s.seq.Add(1)), Key: req.PathValue("key"), Value: string(value)}
	raw, _ := json.Marshal(c)
	if len(raw) > maxCommand {
		http.Error(w, fmt.Sprintf("key and value over %d bytes", maxCommand), http.StatusRequestEntityTooLarge)
		return
	}
	start := time.Now()
	done, ok := s.r.Submit(raw)
	if !ok {
		http.Error(w, "not accepting commands: starting, or too many waiting", http.StatusServiceUnavailable)
		return
	}
	select {
	case <-done:
		_, _ = fmt.Fprintf(w, "committed in %v\n", time.Since(start).Round(time.Microsecond))
	case <-time.After(commitWait):
		http.Error(w, "not committed yet; it may still commit", http.StatusGatewayTimeout)
	case <-req.Context().Done():
	}
}

func (s *server) get(w http.ResponseWriter, req *http.Request) {
	s.mu.Lock()
	v, ok := s.kv[req.PathValue("key")]
	s.mu.Unlock()
	if !ok {
		http.NotFound(w, req)
		return
	}
	_, _ = fmt.Fprintln(w, v)
}

func (s *server) all(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	kv := maps.Clone(s.kv)
	s.mu.Unlock()
	writeJSON(w, kv)
}

func (s *server) metrics(w http.ResponseWriter, _ *http.Request) {
	st := s.r.Stats()
	s.mu.Lock()
	recent := append([]string{}, s.recent...)
	s.mu.Unlock()
	writeJSON(w, map[string]any{
		"id":                   s.id,
		"round":                st.Round,
		"blocks":               st.Blocks,
		"commands":             st.Commands,
		"client_latency_ms":    ms(st.SubmitToCommit),
		"propose_to_commit_ms": ms(st.ProposeToCommit),
		"dropped":              st.OutboundDropped,
		"rejected":             st.Rejected,
		"declined":             st.Declined,
		"blocks_per_s":         s.blockRate(st.Blocks),
		"recent":               recent,
	})
}

// blockRate is the mean committed blocks per second since the first round.
func (s *server) blockRate(blocks int) float64 {
	start := s.start.Load()
	if start == nil {
		return 0
	}
	return float64(blocks) / max(time.Since(*start).Seconds(), 1e-3)
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// writeJSON answers with v; any replica's page may read it.
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_ = json.NewEncoder(w).Encode(v)
}
