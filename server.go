package quicpipe

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/hf/quicpacket"
)

type Association struct {
	ConnectionIDs [][]byte
	Addr          net.Addr
}

var ErrAssociationNotFound = errors.New("quicpipe: association for this connection ID does not exist")

type Store interface {
	PutAssociation(ctx context.Context, association Association) error
	GetAssociation(ctx context.Context, cid []byte) (Association, error)
}

type MapStore struct {
	sync.Mutex

	Map map[string]net.Addr
	XDP interface {
		AddIPv4Redirect(addr *net.UDPAddr, cids ...[]byte) error
	}
}

func NewMapStore() *MapStore {
	return &MapStore{
		Map: make(map[string]net.Addr),
	}
}

func (m *MapStore) PutAssociation(ctx context.Context, association Association) error {
	func() {
		m.Lock()
		defer m.Unlock()

		for _, cid := range association.ConnectionIDs {
			s := hex.EncodeToString(cid)
			m.Map[s] = association.Addr
		}
	}()

	if m.XDP != nil {
		switch association.Addr.(type) {
		case *net.UDPAddr:
			fmt.Println("adding XDP association")
			if err := m.XDP.AddIPv4Redirect(association.Addr.(*net.UDPAddr), association.ConnectionIDs...); err != nil {
				return err
			}
		}
	}

	return nil
}

func (m *MapStore) GetAssociation(ctx context.Context, cid []byte) (Association, error) {
	s := hex.EncodeToString(cid)

	m.Lock()
	defer m.Unlock()

	addr, ok := m.Map[s]
	if ok {
		return Association{
			Addr: addr,
		}, nil
	}

	return Association{}, ErrAssociationNotFound
}

type serverConn struct {
	ctx context.Context

	pconn net.PacketConn
	store Store
}

func isHTTP3ConnectionID(cid []byte) bool {
	// high bit is set
	return (cid[0] & 0x80) != 0
}

func (c *serverConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.pconn.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}

		packet, err := quicpacket.Parse(p[:n], StandardQUICConnectionIDLength)
		if err != nil {
			// unable to parse packet, send to server
			return n, addr, nil
		}

		if packet.Form == quicpacket.LongForm {
			if isHTTP3ConnectionID(packet.SourceConnectionID) {
				return n, addr, nil
			}
		} else {
			if isHTTP3ConnectionID(packet.DestinationConnectionID) {
				return n, addr, nil
			}
		}

		assoc, err := c.store.GetAssociation(c.ctx, packet.DestinationConnectionID)
		if errors.Is(err, ErrAssociationNotFound) {
			// no destination
		} else if err != nil {
			// error
			return 0, nil, err
		} else {
			// forward
			if _, err := c.pconn.WriteTo(p[:n], assoc.Addr); err != nil {
				return 0, nil, err
			}
		}
	}
}

func (c *serverConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return c.pconn.WriteTo(p, addr)
}

func (c *serverConn) Close() error {
	return c.pconn.Close()
}

func (c *serverConn) SetReadDeadline(t time.Time) error {
	return c.pconn.SetReadDeadline(t)
}

func (c *serverConn) SetWriteDeadline(t time.Time) error {
	return c.pconn.SetWriteDeadline(t)
}

func (c *serverConn) SetDeadline(t time.Time) error {
	return c.pconn.SetDeadline(t)
}

func (c *serverConn) LocalAddr() net.Addr {
	return c.pconn.LocalAddr()
}

func (c *serverConn) Register(ctx context.Context, cid []byte, num int, addr net.Addr) error {
	generator := NewConnectionIDGenerator(cid, false)
	ids := make([][]byte, 0, num)

	for i := 0; i < num; i += 1 {
		cid, err := generator.GenerateConnectionIDBytes()
		if err != nil {
			return err
		}

		ids = append(ids, cid)
	}

	err := c.store.PutAssociation(ctx, Association{
		ConnectionIDs: ids,
		Addr:          addr,
	})
	if err != nil {
		return err
	}

	return nil
}

type ServerConnection interface {
	net.PacketConn

	Register(ctx context.Context, cid []byte, num int, addr net.Addr) error
}

func NewServerConnection(ctx context.Context, pconn net.PacketConn, store Store) ServerConnection {
	return &serverConn{
		ctx:   ctx,
		pconn: pconn,
		store: store,
	}
}
