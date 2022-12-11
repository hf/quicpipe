package quicket

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
)

type dialConn struct {
	tx uint32

	ctx context.Context
	cfg *config

	pconn net.PacketConn

	quicConn      quic.Connection
	quicEarlyConn quic.EarlyConnection
}

func (c *dialConn) SetReadDeadline(t time.Time) error {
	return c.pconn.SetReadDeadline(t)
}

func (c *dialConn) SetWriteDeadline(t time.Time) error {
	return c.pconn.SetWriteDeadline(t)
}

func (c *dialConn) SetDeadline(t time.Time) error {
	return c.pconn.SetDeadline(t)
}

func (c *dialConn) Close() error {
	return c.pconn.Close()
}

func (c *dialConn) LocalAddr() net.Addr {
	return c.pconn.LocalAddr()
}

func (c *dialConn) Connection() quic.Connection {
	return c.quicConn
}

func (c *dialConn) EarlyConnection() quic.EarlyConnection {
	return c.quicEarlyConn
}

func (c *dialConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return c.pconn.ReadFrom(p)
}

func (c *dialConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	tx := atomic.AddUint32(&c.tx, 1)

	if tx == 1 {
		return c.writeToInitial(p, addr)
	}

	return c.pconn.WriteTo(p, addr)
}

func (c *dialConn) writeToInitial(p []byte, addr net.Addr) (int, error) {
	req, resh, err := c.cfg.dial.fn(c.ctx, p, c.cfg.p2p.qcfg.ConnectionIDGenerator.(*ConnectionIDGenerator).Key)
	if err != nil {
		return 0, err
	}

	quicrt := &http3.RoundTripper{
		QuicConfig: c.cfg.relay.qcfg,
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, qcfg *quic.Config) (quic.EarlyConnection, error) {
			udpAddr, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				return nil, err
			}

			if c.cfg.relay.tls != nil {
				c.cfg.relay.tls(ctx, tlsCfg)
			}

			return quic.DialEarlyContext(ctx, c, udpAddr, addr, tlsCfg, qcfg)
		},
	}

	quicclient := &http.Client{
		Transport: quicrt,
	}

	resp, err := quicclient.Do(req)
	if err != nil {
		return 0, err
	}

	if err := resh(c.ctx, resp); err != nil {
		quicrt.Close()

		return 0, err
	}

	if err := quicrt.Close(); err != nil {
		return 0, err
	}

	return len(p), nil
}

func Dial(ctx context.Context, pconn net.PacketConn, p2phost string, options ...Option) (Connection, error) {
	cfg := &config{}

	for _, option := range options {
		if err := option(cfg); err != nil {
			return nil, err
		}
	}

	req, _, err := cfg.dial.fn(ctx, nil, nil)
	if err != nil {
		return nil, err
	}

	udpAddr, err := net.ResolveUDPAddr("udp", req.URL.Host)
	if err != nil {
		return nil, err
	}

	conn := &dialConn{
		ctx:   ctx,
		pconn: pconn,
		cfg:   cfg,
	}

	qconn, err := quic.DialContext(ctx, conn, udpAddr, p2phost, cfg.p2p.tls, cfg.p2p.qcfg)
	if err != nil {
		return nil, err
	}

	conn.quicConn = qconn

	return conn, err
}
