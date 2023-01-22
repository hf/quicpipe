package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/hf/quicpipe"
	"github.com/lucas-clemente/quic-go"
)

func createCertificate() []tls.Certificate {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		IsCA:         true,
		PublicKey:    pub,
		NotBefore:    time.Now().UTC(),
		NotAfter:     time.Now().UTC().AddDate(100, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		panic(err)
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}

	return []tls.Certificate{
		{
			Certificate: [][]byte{der},
			PrivateKey:  priv,
			Leaf:        leaf,
		},
	}
}

func acceptResponse(ctx context.Context, response *http.Response) error {
	return nil
}

func acceptRequest(ctx context.Context, cid []byte) (*http.Request, func(ctx context.Context, response *http.Response) error, error) {
	buffer := bytes.NewBuffer(make([]byte, 0, os.Getpagesize()))

	if cid != nil {
		if err := json.NewEncoder(buffer).Encode(map[string]any{
			"key": cid,
			"num": 10, // there will be at most 10 connection ids
		}); err != nil {
			return nil, nil, err
		}
	}

	req, err := http.NewRequest(http.MethodPost, "https://"+os.Getenv("QHOST")+"/v1/register", buffer)
	if err != nil {
		return nil, nil, err
	}

	req = req.WithContext(ctx)

	return req, acceptResponse, nil
}

func main() {
	stdin := bufio.NewReaderSize(os.Stdin, 10*1024)

	data, err := stdin.ReadString('\n')
	if err != nil {
		panic(err)
	}

	var packetData struct {
		Packet []byte `json:"packet"`
	}

	if err := json.Unmarshal([]byte(data), &packetData); err != nil {
		panic(err)
	}

	udpconn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		panic(err)
	}

	fmt.Printf("accepter: %s %d\n", udpconn.LocalAddr().String(), len(packetData.Packet))

	qket, err := quicpipe.Accept(
		context.Background(),
		udpconn,
		packetData.Packet,
		quicpipe.WithPointToPointQUICConfig(
			&quic.Config{
				HandshakeIdleTimeout: time.Hour,
			},
			&tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"EXAMPLE"},
				Certificates:       createCertificate(),
			}),
		quicpipe.WithRelayQUICConfig(nil),
		quicpipe.WithRelayTLSConfig(func(ctx context.Context, tlscfg *tls.Config) error {
			tlscfg.InsecureSkipVerify = true
			return nil
		}),
		quicpipe.WithAcceptRequest(acceptRequest),
	)
	if err != nil {
		panic(err)
	}

	fmt.Printf("accept-listen\n")

	qconn := qket.Connection()
	stream, err := qconn.AcceptStream(context.Background())
	if err != nil {
		panic(err)
	}

	fmt.Printf("stream-opened\n")

	os.Stdout.ReadFrom(stream)
}
