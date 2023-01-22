package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/hf/quicpipe"
	"github.com/lucas-clemente/quic-go"
)

func dialResponse(ctx context.Context, res *http.Response) error {
	return nil
}

func dialRequest(ctx context.Context, packet, cid []byte) (*http.Request, func(ctx context.Context, res *http.Response) error, error) {
	buffer := bytes.NewBuffer(make([]byte, 0, os.Getpagesize()))

	if packet != nil && cid != nil {
		if err := json.NewEncoder(buffer).Encode(map[string]any{
			"key": cid,
			"num": 10, // there will be at most 10 connection ids
		}); err != nil {
			return nil, nil, err
		}

		fmt.Println("ADD THE FOLLOWING LINE TO /tmp/packet.json")

		oob, err := json.Marshal(map[string]any{
			"packet": packet,
		})
		if err != nil {
			return nil, nil, err
		}

		fmt.Printf("%s\n\n", oob)
	}

	req, err := http.NewRequest(http.MethodPost, "https://"+os.Getenv("QHOST")+"/v1/register", buffer)
	if err != nil {
		return nil, nil, err
	}

	req = req.WithContext(ctx)

	return req, dialResponse, nil
}

func main() {
	udpconn, err := net.ListenUDP("udp4", &net.UDPAddr{
		//IP: net.IPv4(127, 0, 0, 1),
	})
	if err != nil {
		panic(err)
	}

	fmt.Printf("dialer: %s\n", udpconn.LocalAddr().String())

	qket, err := quicpipe.Dial(
		context.Background(),
		udpconn,
		"sni.local",
		quicpipe.WithPointToPointQUICConfig(
			&quic.Config{
				HandshakeIdleTimeout: time.Hour,
			},
			&tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"EXAMPLE"},
			}),
		quicpipe.WithRelayQUICConfig(nil),
		quicpipe.WithRelayTLSConfig(func(ctx context.Context, tlscfg *tls.Config) error {
			tlscfg.InsecureSkipVerify = true
			return nil
		}),
		quicpipe.WithDialRequest(dialRequest),
	)

	if err != nil {
		panic(err)
	}

	fmt.Printf("started\n")

	qconn := qket.Connection()
	stream, err := qconn.OpenStreamSync(context.Background())
	if err != nil {
		panic(err)
	}

	fmt.Printf("stream opened\n")

	_, err = stream.Write([]byte("initial hello\n"))
	if err != nil {
		panic(err)
	}

	for {
		_, err := stream.Write([]byte("hello\n"))
		if err != nil {
			panic(err)
		}

		time.Sleep(1 * time.Second)
	}

	fmt.Printf("done\n")
}
