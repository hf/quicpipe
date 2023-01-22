// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <linux/udp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct cid
{
  __u8 cid[12];
};

struct redirect4
{
  __be32 addr;
  __be16 port;
};

struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 32);
  __type(key, __be16);
  __type(value, __u8);
} port_map SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 2 * 1024 * 1024 /* 36 MB for ~2m entries */);
  __type(key, struct cid);
  __type(value, struct redirect4);
} redirect4_map SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 64 * 1024 /* 64kB for ~5k entries */);
} rejected_cids_rb SEC(".maps");

static __always_inline void
copy_ethaddr(unsigned char dst[6], const unsigned char src[6])
{
#pragma clang loop unroll(full)
  for (int i = 0; i < 6; i += 1) {
    dst[i] = src[i];
  }
}

static __always_inline void
copy_cid(__u8 dst[12], const __u8 src[12])
{
#pragma clang loop unroll(full)
  for (int i = 0; i < 12; i += 1) {
    dst[i] = src[i];
  }
}

static __always_inline __sum16
ipv4_checksum(void* addr)
{
  // from: https://datatracker.ietf.org/doc/html/rfc1071#section-4.1
  __u32 sum = 0;

  __u8* baddr = addr;

#pragma clang loop unroll(full)
  for (int i = 0; i < sizeof(struct iphdr); i += 2) {
    sum += (((__sum16)baddr[i + 0]) << 8) | ((__sum16)baddr[i + 1]);
    if (sum >> 16) {
      sum = (sum & 0xffff) + (sum >> 16);
    }
  }

  // because there are no options in the header, no need for padding
  if (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  return bpf_htons(~sum);
}

static __always_inline int
is_http3(const __u8* cid)
{
  return (cid[0] & 0x80) != 0;
}

static __always_inline int
handle_quic4(struct ethhdr* eth,
             struct iphdr* ipv4,
             struct udphdr* udp,
             void* data,
             void* data_end)
{
  if (data + 1 > data_end) {
    // not a QUIC packet
    return XDP_DROP;
  }

  __u8* udata = data;

  if ((udata[0] & 0x40) == 0) {
    // not a QUIC packet
    return XDP_DROP;
  }

  struct cid* dst = NULL;

  if ((udata[0] & 0x80) == 0) {
    // short form
    if (data + 1 + sizeof(struct cid) > data_end) {
      // not a QUIC packet
      return XDP_DROP;
    }

    dst = data + 1;
  } else {
    // long form packet with weird destination length, send to userspace

    return XDP_PASS;
  }

  if (is_http3(dst->cid)) {
    // destination is HTTP3
    return XDP_PASS;
  }

  void* r4value = bpf_map_lookup_elem(&redirect4_map, dst);

  if (r4value != NULL) {
    struct redirect4* r4 = r4value;

    unsigned char swp[6];
    copy_ethaddr(swp, eth->h_dest);
    copy_ethaddr(eth->h_source, eth->h_dest);
    copy_ethaddr(eth->h_dest, swp);

    ipv4->saddr = ipv4->daddr;
    ipv4->daddr = r4->addr;
    ipv4->ttl = 64;
    ipv4->tos = 0;
    ipv4->id = 0;
    ipv4->frag_off = 0;
    ipv4->check = 0;
    ipv4->check = ipv4_checksum(ipv4);

    udp->source = udp->dest;
    udp->dest = r4->port;
    udp->check = 0; // checksum is optional in UDP over IPv4

    return XDP_TX;
  }

  // unable to find destination to redirect

  void* rejected_cid =
    bpf_ringbuf_reserve(&rejected_cids_rb, sizeof(struct cid), 0);

  if (rejected_cid != NULL) {
    copy_cid(rejected_cid, dst->cid);

    bpf_ringbuf_submit(rejected_cid, 0);
  }

  return XDP_DROP;
}

static __always_inline int
handle_udp4(struct ethhdr* eth, struct iphdr* ipv4, void* data, void* data_end)
{
  if (data + sizeof(struct udphdr) > data_end) {
    return XDP_PASS;
  }

  struct udphdr* udp = data;

  void* portvalue = bpf_map_lookup_elem(&port_map, &(udp->dest));

  if (portvalue == NULL) {
    // not a Quicpipe packet
    return XDP_PASS;
  }

  return handle_quic4(eth, ipv4, udp, data + sizeof(struct udphdr), data_end);
}

static __always_inline int
handle_ipv4(struct ethhdr* eth, void* data, void* data_end)
{
  if (data + sizeof(struct iphdr) > data_end) {
    return XDP_PASS;
  }

  struct iphdr* ipv4 = data;

  if ((ipv4->ihl & 0x04) > 5) {
    // options present
    // if changing this, update ipv4_checksum
    return XDP_PASS;
  }

  if (ipv4->protocol == 0x11) {
    // UDP
    return handle_udp4(eth, ipv4, data + sizeof(struct iphdr), data_end);
  }

  return XDP_PASS;
}

static __always_inline int
handle_ipv6(struct ethhdr* eth, void* data, void* data_end)
{
  // not supported
  return XDP_PASS;
}

SEC("xdp")
int
xdp_quicpipe(struct xdp_md* ctx)
{
  void* data = (void*)(long)ctx->data;
  void* data_end = (void*)(long)ctx->data_end;

  if (data + sizeof(struct ethhdr) > data_end) {
    return XDP_PASS;
  }

  struct ethhdr* eth = data;

  if (eth->h_proto == bpf_htons(ETH_P_IP)) {
    return handle_ipv4(eth, data + sizeof(struct ethhdr), data_end);
  } else if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
    return handle_ipv6(eth, data + sizeof(struct ethhdr), data_end);
  }

  return XDP_PASS;
}
