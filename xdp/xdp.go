package xdp

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go quicketxdp xdp.c -- -I/usr/include -I.

import (
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// XDPLink lets you interact with Quicket's eBPF XDP filter.
type XDPLink struct {
	objs  quicketxdpObjects
	links []link.Link

	rbreader *ringbuf.Reader
	rbpool   sync.Pool
}

// Open loads the eBPF code. You should call Attach and AttachPort to load the
// code on an interface and activate it on a UDP port.
func Open() (*XDPLink, error) {
	link := &XDPLink{}

	if err := loadQuicketxdpObjects(&link.objs, nil); err != nil {
		return nil, err
	}

	rbreader, err := ringbuf.NewReader(link.objs.RejectedCidsRb)
	if err != nil {
		return nil, err
	}

	link.rbreader = rbreader
	link.rbpool.New = func() interface{} {
		return &ringbuf.Record{
			RawSample: make([]byte, 12),
		}
	}

	return link, nil
}

// ErrXDPLinkClose is an error when closing fails (which can fail in multiple
// errors).
type ErrXDPLinkClose struct {
	Errors []error
}

func (e ErrXDPLinkClose) Error() string {
	var errs []string
	for _, err := range e.Errors {
		errs = append(errs, err.Error())
	}

	return "qucket/xdp: close failed: " + strings.Join(errs, ", ")
}

// Close closes the eBPF XDP filter, releasing it from all attached interfaces.
func (l *XDPLink) Close() error {
	var errors []error
	for _, link := range l.links {
		if err := link.Close(); err != nil {
			errors = append(errors, err)
		}
	}

	if err := l.rbreader.Close(); err != nil {
		errors = append(errors, err)
	}

	if err := l.objs.Close(); err != nil {
		errors = append(errors, err)
	}

	return ErrXDPLinkClose{
		Errors: errors,
	}
}

// Attach attaches the eBPF filter to the provided interface.
func (l *XDPLink) Attach(iface *net.Interface) error {
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   l.objs.XdpQuicket,
		Interface: iface.Index,
	})
	if err != nil {
		return err
	}

	l.links = append(l.links, link)

	return nil
}

func htons(i uint16) uint16 {
	var arr [2]byte
	b := arr[:]
	binary.LittleEndian.PutUint16(b, i)
	return binary.BigEndian.Uint16(b)
}

func htonl(i uint32) uint32 {
	var arr [4]byte
	b := arr[:]
	binary.LittleEndian.PutUint32(b, i)
	return binary.BigEndian.Uint32(b)
}

// AttachPort activates the eBPF filter on the provided UDP port on all
// attached interfaces.
func (l *XDPLink) AttachPort(port uint16) error {
	return l.objs.PortMap.Put(htons(port), uint8(1))
}

// DetachPort deactivates the eBPF filter on the provided UDP port on all
// attached interfaces.
func (l *XDPLink) DetachPort(port uint16) error {
	return l.objs.PortMap.Delete(htons(port))
}

// AddIPv4Redirect adds the UDP address to the IPv4 redirect map of the eBPF
// filter for all of the provided CIDs. The UDP address is assumed to be IPv4.
func (l *XDPLink) AddIPv4Redirect(addr *net.UDPAddr, cids ...[]byte) error {
	ip := addr.IP.To4()

	var value quicketxdpRedirect4
	value.Port = htons(uint16(addr.Port))
	value.Addr = htonl(
		0 |
			(uint32(ip[0]) << 3 * 8) |
			(uint32(ip[1]) << 2 * 8) |
			(uint32(ip[2]) << 1 * 8) |
			(uint32(ip[3]) << 0 * 8))

	for _, cid := range cids {
		var key quicketxdpCid
		copy(key.Cid[:], cid)

		// in the future maybe use the batch API
		if err := l.objs.Redirect4Map.Put(key, value); err != nil {
			return err
		}
	}

	return nil
}

// RemoveIPv4Redirect removes any redirects assigned to the provided CIDs.
func (l *XDPLink) RemoveIPv4Redirect(cids ...[]byte) error {
	for _, cid := range cids {
		var key quicketxdpCid
		copy(key.Cid[:], cid)

		// in the future maybe use the batch API
		if err := l.objs.Redirect4Map.Delete(key); err != nil {
			return err
		}
	}

	return nil
}

// SetReadDeadline sets the read deadline (for use with ReadRejectedCID).
func (l *XDPLink) SetReadDeadline(deadline time.Time) error {
	l.rbreader.SetDeadline(deadline)

	return nil
}

// ReadRejectedCID reads a single CID from the rejected CID ring buffer. It
// waits until the read dedline set with SetReadDeadline. Once a CID is
// available, the provided callback is called. The CID bytes are available only
// for the duration of the function!
func (l *XDPLink) ReadRejectedCID(fn func(cid []byte) error) error {
	record := l.rbpool.Get().(*ringbuf.Record)
	defer l.rbpool.Put(record)

	if err := l.rbreader.ReadInto(record); err != nil {
		return err
	}

	return fn(record.RawSample)
}
