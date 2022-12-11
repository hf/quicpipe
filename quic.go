package quicket

import (
	"crypto/rand"
	"sync/atomic"

	"github.com/lucas-clemente/quic-go"
	"golang.org/x/crypto/blake2b"
)

const (
	StandardQUICConnectionIDLength = 12
)

func StandardQUICConfig(qcfg *quic.Config, highbit bool) *quic.Config {
	if qcfg == nil {
		qcfg = &quic.Config{}
	}

	generator := NewConnectionIDGenerator(nil, highbit)

	qcfg.ConnectionIDGenerator = generator
	qcfg.DisablePathMTUDiscovery = true
	qcfg.DisableVersionNegotiationPackets = true

	return qcfg
}

type ConnectionIDGenerator struct {
	Key     []byte
	HighBit bool

	counter uint32
}

func NewConnectionIDGenerator(key []byte, highbit bool) *ConnectionIDGenerator {
	c := &ConnectionIDGenerator{
		HighBit: highbit,
		Key:     key,
		counter: 0,
	}

	if c.Key == nil || len(c.Key) == 0 {
		c.Key = make([]byte, 16)
		if _, err := rand.Read(c.Key); err != nil {
			panic(err)
		}
	}

	return c
}

func (c *ConnectionIDGenerator) GenerateConnectionIDBytes() ([]byte, error) {
	counter := atomic.AddUint32(&c.counter, 1)

	h, err := blake2b.New(c.ConnectionIDLen(), c.Key)
	if err != nil {
		return nil, err
	}

	h.Write([]byte{
		byte(counter >> (3 * 8)),
		byte(counter >> (2 * 8)),
		byte(counter >> (1 * 8)),
		byte(counter >> (0 * 8)),
	})

	b := h.Sum(nil)

	if c.HighBit {
		b[0] = b[0] | 0x80
	} else {
		b[0] = b[0] & 0x7F
	}

	return b, nil
}

func (c *ConnectionIDGenerator) GenerateConnectionID() (quic.ConnectionID, error) {
	id, err := c.GenerateConnectionIDBytes()
	if err != nil {
		return quic.ConnectionID{}, err
	}

	return quic.ConnectionIDFromBytes(id), nil
}

func (c *ConnectionIDGenerator) ConnectionIDLen() int {
	return StandardQUICConnectionIDLength
}
