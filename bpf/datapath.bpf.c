/* Copyright (C) 2022-present, Eishun Kondoh <dreamdiagnosis@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU GPL as published by
 * the FSF; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "vmlinux.h"

#include "uapi/linux/pkt_cls.h"
#include "uapi/linux/icmp.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "datapath_kfuncs.h"
#include "datapath_maps.h"
#include "datapath_helpers.h"

#ifndef NEXTHDR_DEST
#define NEXTHDR_DEST 60
#endif

#ifndef MAX_TCP_OPTIONS
#define MAX_TCP_OPTIONS 10
#endif

struct ipv6_encap_opt {
    __u8 encap_limit;
    __u8 len;
    __u8 tel;
    __u8 padN_type;
    __u8 padN_len;
    __u8 padN_pad;
};

struct dp_context {
    struct __sk_buff *skb;
    struct bridge_iface *br;
    struct bpf_dynptr *ptr;
    struct iphdr *iphdr_inner;
    struct ipv6hdr *iphdr_outer;
    struct tcphdr *tcph;
    __u16 mtu_result;
    __u64 *offset;
};

#define AF_INET 2
#define AF_INET6 10
#define ETH_HLEN 14
#define ETH_ALEN 6

#define ICMP_TOOBIG_SIZE 98
#define ICMP_TOOBIG_PAYLOAD_SIZE 92

#define ICMP4_HEADROOM sizeof(struct iphdr) + sizeof(struct icmphdr)
#define IPIP6_ENCAP_SZ                                                                   \
    (sizeof(struct ipv6hdr) + sizeof(struct ipv6_opt_hdr) + sizeof(struct ipv6_encap_opt))

// Transforms an IPv4 payload into an ICMPv4 "Too Big" error message.
// This function changes the packet structure to send an ICMP error
// when the MTU size is exceeded.
static __always_inline int
transform_ip4_to_icmp4_error(struct dp_context *ctx)
{
    struct iphdr iphdr = {0};
    struct icmphdr icmp4 = {0};

    __u32 headroom = ICMP4_HEADROOM;
    __u32 checksum = 0;
    __u64 offset = ETH_HLEN;

    if (bpf_skb_change_tail(ctx->skb, headroom + ICMP_TOOBIG_SIZE, 0))
        return -1;
    if (bpf_skb_change_head(ctx->skb, headroom, 0))
        return -1;

    iphdr.version = 4;
    iphdr.ihl = 5;
    iphdr.tos = 0;
    iphdr.ttl = 0x40;
    iphdr.protocol = IPPROTO_ICMP;
    iphdr.tot_len = bpf_htons(ICMP_TOOBIG_SIZE + headroom - sizeof(struct ethhdr));
    iphdr.check = 0;
    iphdr.daddr = ctx->iphdr_inner->saddr;
    iphdr.saddr = ctx->br->ipaddr;
    ipv4_checksum(&iphdr);

    if (bpf_dynptr_write(ctx->ptr, offset, &iphdr, sizeof(struct iphdr), 0))
        return -1;
    offset += sizeof(struct iphdr);

    icmp4.type = ICMP_DEST_UNREACH;
    icmp4.code = ICMP_FRAG_NEEDED;
    icmp4.un.frag.mtu = bpf_htons(ctx->mtu_result - IPIP6_ENCAP_SZ);
    icmp4.checksum = 0;

    if (bpf_dynptr_write(ctx->ptr, offset, &icmp4, sizeof(struct icmphdr), 0))
        return -1;

    void *data = (void *)(long)ctx->skb->data;
    void *data_end = (void *)(long)ctx->skb->data_end;
    if (data + (ICMP_TOOBIG_SIZE + headroom) > data_end)
        return -1;
    struct icmphdr *icmp_hdr;

    if (data + offset > data_end)
        return -1;
    icmp_hdr = data + offset;
    if (!icmp_hdr)
        return -1;
    ipv4_csum(icmp_hdr, ICMP_TOOBIG_PAYLOAD_SIZE, &checksum);
    icmp_hdr->checksum = checksum;

    return 0;
}

// Sets the FIB (Forwarding Information Base) lookup parameters for IPv4 packets.
// Configures source and destination IPv4 addresses for FIB lookup.
static __always_inline void
set_fib_parameters_ipv4(struct bpf_fib_lookup *fib, struct dp_context *ctx)
{
    fib->family = AF_INET;
    fib->ipv4_src = ctx->iphdr_inner->saddr;
    fib->ipv4_dst = ctx->iphdr_inner->daddr;
}

// Sets the FIB lookup parameters for IPv6 packets.
// Configures source and destination IPv6 addresses for FIB lookup.
static __always_inline void
set_fib_parameters_ipv6(struct bpf_fib_lookup *fib, struct dp_context *ctx)
{
    fib->family = AF_INET6;
    // fib->tot_len = bpf_ntohs(ctx->iphdr_inner->tot_len) + IPIP6_ENCAP_SZ;

    struct in6_addr *src = (struct in6_addr *)fib->ipv6_src;
    struct in6_addr *dst = (struct in6_addr *)fib->ipv6_dst;
    *src = ctx->iphdr_outer->saddr;
    *dst = ctx->iphdr_outer->daddr;
}

// Forwards the packet based on the FIB lookup results.
// Handles different forwarding actions based on lookup outcome.
static __always_inline int
forward_packet_fib(struct dp_context *ctx, struct bpf_fib_lookup *fib, __u16 proto)
{
    struct ethhdr *eth;

    __s32 ret = bpf_fib_lookup(ctx->skb, fib, sizeof(*fib), 0);
    if (ret == BPF_FIB_LKUP_RET_NOT_FWDED || ret < 0)
        return TC_ACT_OK;

    if (zeroize_ethhdr(ctx->ptr, ctx->skb, eth, proto))
        return TC_ACT_SHOT;

    if (ret == BPF_FIB_LKUP_RET_NO_NEIGH) {
        struct bpf_redir_neigh nh = {};
        nh.nh_family = fib->family;
        if (proto == ETH_P_IP)
            memcpy(&nh.ipv4_nh, &fib->ipv4_dst, sizeof(nh.ipv4_nh));
        else if (proto == ETH_P_IPV6)
            memcpy(&nh.ipv6_nh, &fib->ipv6_dst, sizeof(nh.ipv6_nh));
        return bpf_redirect_neigh(fib->ifindex, &nh, sizeof(nh), 0);
    } else if (ret == BPF_FIB_LKUP_RET_SUCCESS) {
        if (set_ethernet(ctx->ptr, 0, fib->dmac, fib->smac, proto))
            return TC_ACT_SHOT;
        return bpf_redirect(fib->ifindex, 0);
    } else if (ret == BPF_FIB_LKUP_RET_FRAG_NEEDED) {
        ctx->mtu_result = fib->mtu_result;
        return BPF_FIB_LKUP_RET_FRAG_NEEDED;
    }

    return TC_ACT_SHOT;
}

// Forwarding logic for IPv4 packets using FIB lookup.
// Parses the IPv4 header and forwards the packet based on FIB lookup.
static __always_inline int
forward_packet_fib_v4(struct dp_context *ctx)
{
    struct bpf_fib_lookup fib = {.ifindex = ctx->skb->ingress_ifindex};
    struct ethhdr *eth;
    struct iphdr iphdr;
    *ctx->offset = ETH_HLEN;

    if (parse_ipv4(ctx->ptr, ctx->offset, &iphdr))
        return TC_ACT_SHOT;

    ctx->iphdr_inner = &iphdr;
    set_fib_parameters_ipv4(&fib, ctx);

    return forward_packet_fib(ctx, &fib, ETH_P_IP);
}

// Forwarding logic for IPv6 packets using FIB lookup.
// Sets up FIB parameters and forwards the IPv6 packet.
static __always_inline int
forward_packet_fib_v6(struct dp_context *ctx)
{
    struct ethhdr *eth;
    struct bpf_fib_lookup fib = {.ifindex = ctx->skb->ingress_ifindex};

    set_fib_parameters_ipv6(&fib, ctx);
    return forward_packet_fib(ctx, &fib, ETH_P_IPV6);
}

// Handles the TCP Maximum Segment Size (MSS) clamping.
// Adjusts the MSS of TCP SYN packets to prevent fragmentation.
static __always_inline int
handle_tcp_mss_clamping(__u32 idx, struct dp_context *ctx)
{
    __u8 opt_kind, opt_size;

    if (parse_tcp_opt_hdr(ctx->ptr, ctx->offset, &opt_kind, &opt_size))
        return 1;
    if (opt_kind == 2) {
        // Clamp TCP MSS (1420 bytes)
        __u16 mss = bpf_htons(1420);
        if (bpf_skb_store_bytes(ctx->skb, *ctx->offset, &mss, sizeof(mss),
                                BPF_F_RECOMPUTE_CSUM)) {
            bpf_printk("failed to parse MSS value");
            return 1;
        }
    }

    *ctx->offset += opt_size;
    return 0;
}

// Processes the Layer 4 protocol, specifically handling TCP.
// Invokes MSS clamping for TCP SYN packets.
static __always_inline int
clamp_tcp_mss(struct __sk_buff *skb, struct dp_context *ctx, struct tcphdr *tcph)
{
    bpf_loop(MAX_TCP_OPTIONS, handle_tcp_mss_clamping, ctx, 0);
    return 0;
}

// Removes the IPv6 encapsulation from the packet.
// Adjusts the packet structure to remove IPv6 headers and decapsulate the payload.
static __always_inline int
process_l4_protocol(struct __sk_buff *skb, struct dp_context *ctx)
{
    if (ctx->iphdr_inner->protocol != IPPROTO_TCP)
        return 0;

    struct tcphdr tcph;

    if (parse_tcp(ctx->ptr, ctx->offset, &tcph))
        return -1;

    ctx->tcph = &tcph;
    if (tcph.syn) {
        if (clamp_tcp_mss(skb, ctx, &tcph))
            return -1;
    }

    return 0;
}

// Encapsulates an IPv4 packet within an IPv6 header.
// Used for IPv4-to-IPv6 transitioning, adding necessary IPv6 headers to the packet.
static __always_inline int
remove_ipv6_encapsulation(struct dp_context *ctx)
{
    struct ipv6hdr ipv6_header_outer;
    struct ipv6_opt_hdr ipv6_option_header;

    __u64 flags = BPF_F_ADJ_ROOM_FIXED_GSO;
    __s32 outer_header_len = IPIP6_ENCAP_SZ;
    __u8 next_header_proto;
    bool is_fragmented;

    // Set the initial offset to the start of the Ethernet header.
    *ctx->offset = ETH_HLEN;

    // Parse the IPv6 header.
    if (parse_ipv6(ctx->ptr, ctx->offset, &ipv6_header_outer, &next_header_proto,
                   &is_fragmented))
        return -1; // Failed to parse IPv6 header

    ctx->iphdr_outer = &ipv6_header_outer;

    if (ipv6_header_outer.nexthdr == NEXTHDR_DEST) {
        if (bpf_skb_load_bytes(ctx->skb, *ctx->offset, &ipv6_option_header,
                               sizeof(ipv6_option_header)) < 0)
            return -1; // Failed to load IPv6 option header

        if (ipv6_option_header.nexthdr == IPPROTO_IPIP) {
            flags |= BPF_F_ADJ_ROOM_DECAP_L3_IPV4;
        } else {
            return 0; // Unsupported next header protocol
        }
    } else {
        return 0; // Unsupported next header protocol
    }

    // Adjust the skb room to remove IPv6 encapsulation.
    if (bpf_skb_adjust_room(ctx->skb, -outer_header_len, BPF_ADJ_ROOM_MAC, flags))
        return -1; // Failed to adjust skb room

    // Process the Layer 4 protocol.
    if (process_l4_protocol(ctx->skb, ctx))
        return -1; // Failed to process Layer 4 protocol

    return 0; // Successful removal of IPv6 encapsulation
}

// Encapsulates an IPv4 packet within an IPv6 header.
// Used for IPv4-to-IPv6 transitioning, adding necessary IPv6 headers to the packet.
static __always_inline int
encapsulate_ipv4_in_ipv6(struct __sk_buff *skb, struct dp_context *ctx)
{
    struct ipv6hdr ip6;
    struct ipv6_opt_hdr dstopt;
    struct ipv6_encap_opt opt;

    __u64 flags = BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_ENCAP_L3_IPV6 |
                  BPF_F_ADJ_ROOM_NO_CSUM_RESET;
    __u32 olen = IPIP6_ENCAP_SZ;
    int fwd_ret;
    *ctx->offset = ETH_HLEN;

    ip6.version = 6;
    ip6.nexthdr = NEXTHDR_DEST;
    ip6.hop_limit = ctx->iphdr_inner->ttl - 1;
    ip6.payload_len = ctx->iphdr_inner->tot_len + bpf_htons(8);
    if (set_ipip6_addr(ip6.saddr.in6_u.u6_addr8, ip6.daddr.in6_u.u6_addr8))
        return TC_ACT_SHOT;
    ctx->iphdr_outer = &ip6;

    dstopt.nexthdr = IPPROTO_IPIP;
    dstopt.hdrlen = 0;
    opt.encap_limit = 0x04;
    opt.len = 1;
    opt.tel = 4;
    opt.padN_type = 0x01;
    opt.padN_len = 1;
    opt.padN_pad = 0x00;

    fwd_ret = forward_packet_fib_v6(ctx);
    if (fwd_ret == BPF_FIB_LKUP_RET_FRAG_NEEDED) {
        if (transform_ip4_to_icmp4_error(ctx))
            return TC_ACT_SHOT;
        fwd_ret = forward_packet_fib_v4(ctx);
        return fwd_ret;
    }

    if (bpf_skb_adjust_room(skb, olen, BPF_ADJ_ROOM_MAC, flags))
        return TC_ACT_SHOT;

    if (bpf_dynptr_write(ctx->ptr, *ctx->offset, &ip6, sizeof(struct ipv6hdr), 0))
        return TC_ACT_SHOT;
    *ctx->offset += sizeof(struct ipv6hdr);

    if (bpf_dynptr_write(ctx->ptr, *ctx->offset, &dstopt, sizeof(struct ipv6_opt_hdr), 0))
        return TC_ACT_SHOT;
    *ctx->offset += sizeof(struct ipv6_opt_hdr);

    if (bpf_dynptr_write(ctx->ptr, *ctx->offset, &opt, sizeof(struct ipv6_encap_opt), 0))
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

// Decapsulates an IPv6 packet and checks if it should be forwarded as IPv4.
// If the packet is encapsulated as IPIP, it forwards the inner IPv4 packet.
static __always_inline int
decap_ip6_ipip6(struct __sk_buff *skb, struct dp_context *ctx)
{
    if (remove_ipv6_encapsulation(ctx))
        return TC_ACT_SHOT;

    if (ctx->iphdr_outer->nexthdr == NEXTHDR_DEST) {
        return forward_packet_fib_v4(ctx);
    } else {
        return TC_ACT_OK;
    }
}

// Handles IPv4 packets received by the bridge interface.
// Checks if the packet is destined for the bridge IP interface and encapsulates it in
// IPv6 if needed.
static __always_inline int
handle_ipv4_packet(struct __sk_buff *skb, struct dp_context *ctx)
{
    struct iphdr iphdr;

    if (parse_ipv4(ctx->ptr, ctx->offset, &iphdr))
        return TC_ACT_SHOT;

    // pass the packet if destine to the bridge IP interface
    if (iphdr.daddr == ctx->br->ipaddr)
        return TC_ACT_OK;

    // Encap the ipv4 packet into ipv6 header with extensions
    ctx->iphdr_inner = &iphdr;
    if (process_l4_protocol(skb, ctx))
        return TC_ACT_SHOT;

    return encapsulate_ipv4_in_ipv6(skb, ctx);
}

// eBPF event hooks

// eBPF hook for processing packets entering the bridge interface.
// Parses Ethernet headers and handles IPv4 packets.
SEC("tc") int bridge_packet_in(struct __sk_buff *skb)
{
    struct bpf_dynptr ptr;
    struct bridge_iface br_iface;
    struct dp_context ctx;

    struct ethhdr ethhdr;
    __u64 offset = 0;

    ctx.br = &br_iface;
    ctx.offset = &offset;
    ctx.skb = skb;

    if (get_br_iface_config(&br_iface))
        return TC_ACT_SHOT;

    if (bpf_dynptr_from_skb(ctx.skb, 0, &ptr))
        return TC_ACT_SHOT;

    if (parse_ethernet(&ptr, ctx.offset, &ethhdr))
        return TC_ACT_SHOT;

    ctx.ptr = &ptr;
    // handler for bridging packets. we simply pass to the kernel stack.
    if (!MAC_CMP(ethhdr.h_dest, br_iface.hwaddr) ||
        !(ethhdr.h_proto == __bpf_constant_htons(ETH_P_IP)))
        return TC_ACT_OK;

    return handle_ipv4_packet(skb, &ctx);
}

// eBPF hook for processing packets entering the gateway interface.
// Decapsulates IPv6 packets and handles them accordingly.
SEC("tc") int gateway_packet_in(struct __sk_buff *skb)
{
    struct dp_context ctx;
    struct bpf_dynptr ptr;

    struct ethhdr ethhdr;
    __u64 offset = 0;

    ctx.ptr = &ptr;
    ctx.offset = &offset;
    ctx.skb = skb;

    if (bpf_dynptr_from_skb(skb, 0, ctx.ptr))
        return TC_ACT_SHOT;

    switch (skb->protocol) {
    case __bpf_constant_htons(ETH_P_IPV6):
        return decap_ip6_ipip6(skb, &ctx);
    default:
        return TC_ACT_OK;
    }
}

char __license[] SEC("license") = "Dual MIT/GPL";
