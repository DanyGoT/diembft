// Package diemnet is the Gorums transport for DiemBFT. Two files here see the
// Gorums and gRPC layer, and nothing else below them does: server.go
// implements the generated server interface and gorums.go calls the generated
// client functions. The messages cross it as generated diempb types, which
// package diem consumes directly; check-deps keeps Gorums out of diem.
package diemnet

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/DanyGoT/diembft/diem"
	"github.com/DanyGoT/diembft/diemcrypto"
	"github.com/DanyGoT/diembft/proto/diempb"
	"github.com/relab/gorums"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// fetchTimeout bounds one block request. A peer that holds the block answers
// at once, so the bound only matters when none does.
const fetchTimeout = time.Second

// Config is what the transport and its inbound handlers need.
type Config struct {
	ID       uint32
	Verifier *diem.Verifier
	Network
}

// Network is where a replica listens and how it reaches its peers.
type Network struct {
	Peers  map[uint32]string // every replica's address, this one included
	Listen string            // ":0" picks a free port; read it back with Addr

	// TLS, if set, runs every stream over mutual TLS, and Gorums then
	// authenticates each peer by its certificate, so ServerContext.SenderID
	// names the replica that sent a message. Without it, streams are
	// unencrypted and the sender ID is only claimed.
	TLS *tls.Config

	DialOptions   []gorums.DialOption
	ServerOptions []gorums.ServerOption

	// Server, if set, is used instead of creating one, and Listen, Peers, TLS,
	// DialOptions and ServerOptions are then ignored. That is how LocalServers
	// is used: WithPeers needs every peer address before any server exists, so
	// the listeners have to be allocated first. The caller installs
	// VerifyInterceptor on it, counting into Rejected.
	Server   *gorums.Server
	Rejected *atomic.Uint64
}

// peerAddr adapts a plain address to gorums.NodeAddress.
// GORUMS: WithNodes requires an Addr() string method, so a map[uint32]string
// cannot be handed over directly; and WithNodeList, the alternative, numbers
// nodes from a process-wide registry, so a second server in the same process
// would get IDs n+1..2n rather than 1..n.
type peerAddr string

func (a peerAddr) Addr() string { return string(a) }

// peerNode is a peer that Gorums authenticates by the identity in its
// certificate.
type peerNode struct {
	addr string
	id   uint32
}

func (n peerNode) Addr() string        { return n.addr }
func (n peerNode) TLSIdentity() string { return diemcrypto.TLSIdentity(n.id) }

// nodes is peers as a Gorums node source, authenticated if secure.
func nodes(peers map[uint32]string, secure bool) gorums.NodeSource {
	if !secure {
		m := make(map[uint32]peerAddr, len(peers))
		for id, addr := range peers {
			m[id] = peerAddr(addr)
		}
		return gorums.WithNodes(m)
	}
	m := make(map[uint32]peerNode, len(peers))
	for id, addr := range peers {
		m[id] = peerNode{addr, id}
	}
	return gorums.WithNodes(m)
}

// security is the dial and server options for c: mutual TLS, or no transport
// security if c is nil. They come first, so that a later dial option that
// sets credentials would override them.
func security(c *tls.Config) (gorums.DialOption, gorums.ServerOption) {
	if c == nil {
		return gorums.WithTransportCredentials(insecure.NewCredentials()), nil
	}
	creds := credentials.NewTLS(c)
	return gorums.WithTransportCredentials(creds),
		gorums.WithGRPCServerOptions(grpc.Creds(creds))
}

// LocalServers is gorums.NewLocalServers for a group of n replicas on
// loopback, with VerifyInterceptor over v counting into rejected. tlsByID, if
// set, holds each replica's TLS configuration, as Network.TLS does. srv and
// dial are added to every replica's server and dial options.
func LocalServers(n int, v *diem.Verifier, rejected *atomic.Uint64, tlsByID map[uint32]*tls.Config, srv []gorums.ServerOption, dial ...gorums.DialOption) ([]*gorums.Server, func(), error) {
	opts := []gorums.LocalServerOption{
		gorums.WithLocalServerOptions(gorums.WithServerInterceptors(VerifyInterceptor(v, rejected))),
		gorums.WithLocalServerOptions(srv...),
		gorums.WithLocalDialOptionsFunc(func(id gorums.ID) []gorums.DialOption {
			d, _ := security(tlsByID[id])
			return append([]gorums.DialOption{d}, dial...)
		}),
	}
	if tlsByID != nil {
		opts = append(opts,
			gorums.WithLocalNodes(func(id gorums.ID, addr string) gorums.NodeAddress { return peerNode{addr, id} }),
			gorums.WithLocalServerOptionsFunc(func(id gorums.ID) []gorums.ServerOption {
				_, s := security(tlsByID[id])
				return []gorums.ServerOption{s}
			}),
		)
	}
	return gorums.NewLocalServers(n, opts...)
}

// Transport is the Gorums implementation of diem.Transport, together with the
// server that receives on the other side.
//
// A send goes straight into Gorums' per-node send queue, sized with
// gorums.WithDialBufferSizes, and returns once queued. A node whose queue is
// full rejects the message, which is counted as a drop, so a peer that stops
// reading cannot block the core. A lost message is what the round timer
// recovers from.
//
// RequestBlock is the one call with a reply, and an addition: DiemBFT §3
// defines no block-sync. It lets a replica that lost a proposal vote again.
type Transport struct {
	srv      *gorums.Server
	peers    gorums.Config
	client   diempb.DiemClient
	handler  *handler
	ver      *diem.Verifier
	rejected *atomic.Uint64

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	dropped atomic.Uint64
}

var _ diem.Transport = (*Transport)(nil)

// New builds the Gorums server, registers the inbound handlers and returns the
// transport over it. Nothing is served until Start.
func New(cfg Config) *Transport {
	// GORUMS, in its favour: WithPeers makes this replica's own ID an in-process
	// local node, so the paper's "broadcast to all replicas, including u itself"
	// works literally. A leader's own proposal returns as a normal inbound
	// message, which is what lets Core treat every message the same way whoever
	// sent it.
	if cfg.Rejected == nil {
		cfg.Rejected = new(atomic.Uint64)
	}
	srv := cfg.Server
	if srv == nil {
		dial, serve := security(cfg.TLS)
		srv = gorums.NewServer(append([]gorums.ServerOption{
			gorums.WithAddr(cfg.Listen),
			gorums.WithPeers(cfg.ID, nodes(cfg.Peers, cfg.TLS != nil), append([]gorums.DialOption{dial}, cfg.DialOptions...)...),
			gorums.WithServerInterceptors(VerifyInterceptor(cfg.Verifier, cfg.Rejected)),
			serve,
		}, cfg.ServerOptions...)...)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Transport{
		srv:      srv,
		peers:    srv.PeerConfig(),
		client:   diempb.NewDiemClient(srv.PeerConfig()),
		handler:  &handler{},
		ver:      cfg.Verifier,
		rejected: cfg.Rejected,
		ctx:      ctx,
		cancel:   cancel,
	}
}

// Start hands verified inbound messages to core under mu, the lock the caller
// serializes every core call with, then serves. It returns immediately.
func (t *Transport) Start(core *diem.Core, mu sync.Locker) {
	t.handler.core, t.handler.mu = core, mu
	t.serve(t.handler)
}

// serve registers h and serves. GORUMS: Server.RegisterHandler writes an
// unsynchronised map that the inbound manager reads once serving starts, so
// registration comes first, and gorumstest.LocalServers — which serves before
// it returns — cannot be used for a replica group; -race flags it.
func (t *Transport) serve(h diempb.DiemServer) {
	diempb.RegisterDiemServer(t.srv, h)
	t.wg.Go(func() {
		_ = t.srv.ListenAndServe() // returns when Stop closes the listener
	})
}

// Stop ends every block fetch and shuts the server down. A send after Stop
// sends nothing and is not counted as a drop.
func (t *Transport) Stop() {
	t.cancel()
	t.srv.Stop()
	t.wg.Wait()
}

// WaitForPeers blocks until every configured peer has connected, or ctx is done.
func (t *Transport) WaitForPeers(ctx context.Context) error {
	want := t.peers.Size()
	return t.srv.WaitForPeers(ctx, func(c gorums.Config) bool { return c.Size() >= want })
}

func (t *Transport) Proposal(p *diempb.ProposalMsg) {
	t.count(t.client.Proposal(t.ctx, p).Send())
}

// Vote unicasts to the leader of the next round, as the paper does: that leader
// is the only replica that will propose over the certificate these votes form.
func (t *Transport) Vote(v *diempb.VoteMsg, to uint32) {
	t.count(diempb.NewDiemNodeClient(t.peers.Node(to)).Vote(t.ctx, v).Send())
}

func (t *Transport) Timeout(m *diempb.TimeoutMsg) {
	t.count(t.client.Timeout(t.ctx, m).Send())
}

// count adds one drop per node a send did not reach: a full send queue, an
// unknown node or an empty configuration.
func (t *Transport) count(err error) {
	if err == nil || t.ctx.Err() != nil {
		return
	}
	if qcErr, ok := errors.AsType[gorums.QuorumCallError](err); ok {
		t.dropped.Add(uint64(qcErr.NumErrors()))
		return
	}
	t.dropped.Add(1)
}

// RequestBlock runs a quorum call to every peer on its own goroutine, so a slow
// fetch holds up no other send. Any reply that passes VerifyBlock is the
// block, so the first such reply goes to the core and the rest are dropped.
// First would take the first reply without checking it.
//
// Stop does not wait for the goroutine, so a fetch may still be waiting for
// the lock after it, and a stopped core ignores it.
func (t *Transport) RequestBlock(id []byte) {
	go t.fetch(id)
}

func (t *Transport) fetch(id []byte) {
	ctx, cancel := context.WithTimeout(t.ctx, fetchTimeout)
	defer cancel()
	req := diempb.BlockHash_builder{Id: id}.Build()
	for r := range t.client.RequestBlock(ctx, req).Results().IgnoreErrors() {
		if t.ver.VerifyBlock(r.Value, id) {
			t.handler.block(r.Value)
			return
		}
	}
}

// Counters is a snapshot of what the transport had to discard. A BFT replica
// cannot act on a send error, so counting is what happens instead.
type Counters struct {
	OutboundDropped uint64
	Rejected        uint64
}

func (t *Transport) Counters() Counters {
	return Counters{
		OutboundDropped: t.dropped.Load(),
		Rejected:        t.rejected.Load(),
	}
}
