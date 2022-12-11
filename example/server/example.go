package main

import (
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
	"time"

	"github.com/go-chi/chi"
	"github.com/hf/quicket"
	"github.com/lucas-clemente/quic-go/http3"
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

func main() {
	udpconn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		panic(err)
	}

	fmt.Printf("addr: %s\n", udpconn.LocalAddr().String())

	conn := quicket.NewServerConnection(
		context.Background(),
		udpconn,
		quicket.NewMapStore(),
	)

	router := chi.NewRouter()
	router.Post("/v1/register", func(w http.ResponseWriter, r *http.Request) {
		var registerReq struct {
			Key []byte `json:"key"`
			Num int    `json:"num"`
		}

		dec := json.NewDecoder(r.Body)
		defer r.Body.Close()

		err := dec.Decode(&registerReq)
		if err != nil {
			w.WriteHeader(400)
			return
		}

		addr, err := net.ResolveUDPAddr("udp", r.RemoteAddr)
		if err != nil {
			panic(err)
		}

		fmt.Printf("registering %v connection IDs for %v\n", registerReq.Num, addr.String())

		err = conn.Register(r.Context(), registerReq.Key, registerReq.Num, addr)
		if err != nil {
			w.WriteHeader(400)
			w.Write([]byte("bad"))
			return
		}

		w.WriteHeader(200)
		w.Write([]byte("OK"))
	})

	server := http3.Server{
		QuicConfig: quicket.StandardQUICConfig(nil, true),
		Handler:    router,
		TLSConfig: http3.ConfigureTLSConfig(&tls.Config{
			Certificates: createCertificate(),
		}),
	}

	server.Serve(conn)
}
