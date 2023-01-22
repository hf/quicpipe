package quicpipe

import (
	"context"
	"crypto/tls"
	"net/http"

	"github.com/lucas-clemente/quic-go"
)

type config struct {
	p2p struct {
		qcfg *quic.Config
		tls  *tls.Config
	}

	relay struct {
		qcfg *quic.Config
		tls  func(ctx context.Context, tlscfg *tls.Config) error
	}

	dial struct {
		fn CreateDialRequestFunc
	}

	accept struct {
		fn CreateAcceptRequestFunc
	}
}

type Option = func(c *config) error

func WithPointToPointQUICConfig(qcfg *quic.Config, tls *tls.Config) Option {
	return func(c *config) error {
		c.p2p.qcfg = StandardQUICConfig(qcfg, false)
		c.p2p.tls = tls

		return nil
	}
}

func WithRelayQUICConfig(qcfg *quic.Config) Option {
	return func(c *config) error {
		c.relay.qcfg = StandardQUICConfig(qcfg, true)

		return nil
	}
}

func WithRelayTLSConfig(tlsfn func(ctx context.Context, tlscfg *tls.Config) error) Option {
	return func(c *config) error {
		c.relay.tls = tlsfn

		return nil
	}
}

type ResponseHandler = func(ctx context.Context, response *http.Response) error

type CreateDialRequestFunc = func(ctx context.Context, packet []byte, cid []byte) (*http.Request, ResponseHandler, error)

func WithDialRequest(fn CreateDialRequestFunc) Option {
	return func(c *config) error {
		c.dial.fn = fn

		return nil
	}
}

type CreateAcceptRequestFunc = func(ctx context.Context, cid []byte) (*http.Request, ResponseHandler, error)

func WithAcceptRequest(fn CreateAcceptRequestFunc) Option {
	return func(c *config) error {
		c.accept.fn = fn

		return nil
	}
}
