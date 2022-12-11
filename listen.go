package quicket

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
)

type acceptConn struct {
	ctx context.Context

	pconn net.PacketConn

	oobPackets chan []byte
	remoteAddr net.Addr

	quicConn      quic.Connection
	quicEarlyConn quic.EarlyConnection

	readDeadline atomic.Value
}

func (c *acceptConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Store(t)

	return nil
}

func (c *acceptConn) SetWriteDeadline(t time.Time) error {
	return c.pconn.SetWriteDeadline(t)
}

func (c *acceptConn) SetDeadline(t time.Time) error {
	c.readDeadline.Store(t)

	return c.pconn.SetWriteDeadline(t)
}

func (c *acceptConn) Close() error {
	return c.pconn.Close()
}

func (c *acceptConn) LocalAddr() net.Addr {
	return c.pconn.LocalAddr()
}

func (c *acceptConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		select {
		case oob := <-c.oobPackets:
			n := copy(p, oob)
			return n, c.remoteAddr, nil

		default:
			// continue
		}

		if err := c.pconn.SetReadDeadline(time.Now().Add(5 * time.Millisecond)); err != nil {
			return 0, nil, err
		}

		n, addr, err := c.pconn.ReadFrom(p)
		if err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				return n, addr, err
			}
		} else {
			// successfully read packets don't trigger deadline
			// exceeded
			return n, addr, err
		}

		rd := c.readDeadline.Load()
		if rd != nil {
			rdt := rd.(time.Time)

			if time.Now().After(rdt) {
				return 0, nil, os.ErrDeadlineExceeded
			}
		}
	}
}

func (c *acceptConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return c.pconn.WriteTo(p, addr)
}

func (c *acceptConn) Connection() quic.Connection {
	return c.quicConn
}

type CreateRequestFunc = func(ctx context.Context, cid []byte, num int) (*http.Request, error)

func Accept(ctx context.Context, pconn net.PacketConn, packet []byte, options ...Option) (Connection, error) {
	cfg := &config{}

	for _, option := range options {
		if err := option(cfg); err != nil {
			return nil, err
		}
	}

	conn := &acceptConn{
		ctx:        ctx,
		pconn:      pconn,
		oobPackets: make(chan []byte),
	}

	quicrt := &http3.RoundTripper{
		QuicConfig: cfg.relay.qcfg,
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, qcfg *quic.Config) (quic.EarlyConnection, error) {
			udpAddr, err := net.ResolveUDPAddr("udp", addr)
			if err != nil {
				return nil, err
			}

			conn.remoteAddr = udpAddr

			if cfg.relay.tls != nil {
				if err := cfg.relay.tls(ctx, tlsCfg); err != nil {
					return nil, err
				}
			}

			return quic.DialEarlyContext(ctx, conn, udpAddr, addr, tlsCfg, qcfg)
		},
	}

	quicclient := &http.Client{
		Transport: quicrt,
	}

	req, resh, err := cfg.accept.fn(ctx, cfg.p2p.qcfg.ConnectionIDGenerator.(*ConnectionIDGenerator).Key)
	if err != nil {
		return nil, err
	}

	res, err := quicclient.Do(req)
	if err != nil {
		return nil, err
	}

	if err := resh(ctx, res); err != nil {
		quicrt.Close()

		return nil, err
	}

	if err := quicrt.Close(); err != nil {
		return nil, err
	}

	go func() {
		conn.oobPackets <- packet
	}()

	qln, err := quic.Listen(conn, cfg.p2p.tls, cfg.p2p.qcfg)
	if err != nil {
		return nil, err
	}

	qconn, err := qln.Accept(ctx)
	if err != nil {
		return nil, err
	}

	conn.quicConn = qconn

	return conn, err
}
