Quicket
=======

Quicket (QUIC + Socket) is a way of establishing point-to-point QUIC
connections between two devices that are unable to directly connect to each
other via traditional means.

For example, devices on the modern internet are often unable to directly talk
to each other due to the use of NAT. Sometimes devices even change their IP
address due to changing their physical location or connectivity status.

Technologies such as WebRTC were aimed at solving this problem. However, they
come from a time where QUIC did not exist and real-time communication between
devices was mainly attempting to solve the video/audio over IP problem. Thus
the complexity of WebRTC is still prohibitive both in system complexity and
cost of operation as well.

Quicket, or this implementation of it at least, attempts to solve this problem
in a novel way, one that is both simpler and cheaper to operate than WebRTC.
It's a proof-of-concept at this stage.

## Quicket protocol

Quicket is really just plain QUIC with some carefully chosen parameters that
enable point-to-point communication.

Whenever `A` wants to open a point-to-point connection to `B` the following
applies:

- `A` is the dialer, `B` is the accepter
- Both have previously exchanged TLS trust information
- Both *always* use 12-byte connection IDs (this can be modified)
- Both assume QUIC version 1, and do no MTU discovery
- `A` produces an intiial packet and discloses its connection IDs to `R`
- `B` receives the inidial handshake out-of-band and discloses its connection
  IDs to `R`
- `A` and `B` talk to `R` via HTTP3 or another QUIC-based protocol
- `R` maps all of `A`'s connection IDs to its public UDP address, and forwards
  packets with such destination IDs to `A`; vice versa for `B`

`R` provides these important features:

- Hole punching: since the connection ID sharing occurs over HTTP3, a UDP hole
  is punched through NAT before the handshake continues between `A` and `B`
- Efficient forwarding: Given that `R` knows all connection IDs that will ever
  be used between `A` and `B`, it only needs to look up destination connection
  IDs for each QUIC packet and forward to the correct destination

Once `A` and `B` are able to reach each other over `R`'s relay service, they
can agree to attempt direct NAT hole punching over UDP. QUIC makes it really
easy for `A` and `B` to migrate their stream over any transmission medium and
address space -- while they can always fall back to using `R`'s services at any
time as a guaranteed fallback. This is why `R` always needs to know all of the
possible connection IDs that `A` and `B` are going to use _through it_.

The initial packet from `A` to `B` can be delivered via `R` or via any other
medium: Apple Push-Notifications, Firebase Cloud Messaging, Bluetooth, camera
via QR code, audio, ...

## Comparison to WebRTC

**Signaling**: WebRTC requires that peers figure out a way to discover (i.e.
dial) each other. This is often done over SIP and requires non-trivial and
sometimes expensive infrastructure to set up well. With Quicket signaling is
"built in" and is based on regular HTTP3 requests. At this time there's no
official request/response encoding standard but applications can design it to
be as complex as they choose, and can use text or binary encodings as well.

**Protocol**: WebRTC uses SCTP (UDP) over DTLS, which has similar but not
equivalent properties with QUIC. QUIC has TLS built in and the connection is
between the peers, rather than through a middlebox. QUIC offers both streams
and datagrams, in various modes, and has excellent privacy features.

**Support**: WebRTC is supported in browsers, while Quicket is not supported in
browsers at this time.

**Architecture**: WebRTC prefers establishing direct connections between peers
(via the ICE framework) but in the modern internet a TURN server (a relay
server) is often and increasingly necessary. TURN servers are expensive to run
since they often do stream processing, re-encoding and re-encrypting. A Quicket
server is a TURN-style server by default and can use optimization techniques
such as eBPF to implement an incredibly cost-effective, privacy preserving
relay.

**End-to-end encryption**: QUIC does not allow unencrypted streams. Furthermore
TLS must be used.. A Quicket relay has no way to decode the traffic between the
peers, given that peers properly exchange certificates that guards against a
middle-person attack. Using QUIC between peers is also a good idea since peers
don't have to reinvent (an insecure) TLS.

## Example

The `example` directory has an example implementing the tree parties. Start
them like so:

Relay server:

```shell
go run github.com/hf/quicket/example/server
```

Copy the port of the listening address, called `<port>`:

```shell
QHOST='127.0.0.1:<port>' go run github.com/hf/quicket/example/dialer
```

Dialer will now attempt to dial the *accepter* (which we're yet to start). To
do this it will print out its initial packet to standard output. Copy the JSON
and add it to a file `/tmp/packet.json`. This simulates the out-of-band
transmission of the QUIC initial packet.

```shell
cat /tmp/packet.json | QHOST='127.0.0.1:<port>' go run github.com/hf/quicket/example/accepter
```

Accepter will now read the initial packet from the file and begin talking to
the dialer over the server. You should see a `hello` message being pritned
every second, this is a message sent from the dialer.

## Further work

This has not been tested on a live network yet. Performance is likely not
great, but can be massively improved. Linux servers can use eBPF to efficiently
implement the relay which also needs to be done.

Some guidelines or standardization of the registration protocol is probably
useful. Right now the examples use a `POST /v1/register` unsecured endpoint to
register their connection IDs, which are derived using Blake2b MACs and a
simple sequential counter.

## License

Copyright &copy; 2022 Stojan Dimitrovski. Some rights reserved.

Licensed under the MIT X11 license. You can get a copy of it in `LICENSE`.

