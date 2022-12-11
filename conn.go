package quicket

import "github.com/lucas-clemente/quic-go"

type Connection interface {
	Connection() quic.Connection
}
