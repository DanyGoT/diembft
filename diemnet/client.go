package diemnet

import (
	"context"
	"crypto/tls"
	"errors"
	"time"

	"github.com/DanyGoT/diembft/diem"
	"github.com/DanyGoT/diembft/proto/diempb"
	"github.com/relab/gorums"
	"google.golang.org/protobuf/types/known/emptypb"
)

var errNoProof = errors.New("diemnet: no replica returned a valid commit proof")

// Client submits commands to every replica and trusts none of them: it takes
// the first proof of commit that its Verifier accepts.
type Client struct {
	client diempb.ClientClient
	close  func()
	ver    *diem.Verifier
}

// Dial connects to the replicas in peers. With tlsConfig, every replica must
// present the certificate of its own ID, and the client presents none, so it
// cannot pass for a replica. ver checks the proofs.
func Dial(peers map[uint32]string, tlsConfig *tls.Config, ver *diem.Verifier, opts ...gorums.DialOption) (*Client, error) {
	dial, _ := security(tlsConfig)
	cfg, closeFn, err := gorums.NewConfig(nodes(peers, tlsConfig != nil), append([]gorums.DialOption{dial, redial}, opts...)...)
	if err != nil {
		return nil, err
	}
	return &Client{client: diempb.NewClientClient(cfg), close: closeFn, ver: ver}, nil
}

// Submit sends cmd to every replica and returns the first reply that proves
// it committed. A reply that fails the check is skipped, as in
// Transport.fetch. ctx bounds the wait.
func (c *Client) Submit(ctx context.Context, cmd *diempb.Command) (*diempb.CommitProof, error) {
	want := cmd.Encode()
	for r := range c.client.Submit(ctx, cmd).Results().IgnoreErrors() {
		if c.ver.VerifyCommit(r.Value, want) {
			return r.Value, nil
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, errNoProof
}

// Ping is an empty call to every replica that returns at the first reply, as
// Submit does: the network's share of Submit's latency.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.client.Ping(ctx, &emptypb.Empty{}).First()
	return err
}

// Ready blocks until every replica answers a Ping, or ctx is done, so that a
// run starts with every connection up, as Barrier does for the replicas.
func (c *Client) Ready(ctx context.Context) error {
	for {
		_, err := c.client.Ping(ctx, &emptypb.Empty{}).All()
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(barrierRetry):
		}
	}
}

// Close closes the connections.
func (c *Client) Close() { c.close() }
