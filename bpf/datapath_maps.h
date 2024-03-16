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

#ifndef __DP_MAP_HELPERS__
#define __DP_MAP_HELPERS__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <string.h>

struct ipip6_config {
    __u8 saddr[16];
    __u8 daddr[16];
} __attribute__((packed));

struct bridge_iface {
    __u32 iface_idx;
    __u8 hwaddr[6];
    __u32 ipaddr;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct ipip6_config);
    __uint(max_entries, 1);
} ipip6_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct bridge_iface);
    __uint(max_entries, 1);
} bridge_iface_conf SEC(".maps");


// BPF map wrapper

static __always_inline int
set_ipip6_addr(__u8 *saddr, __u8 *daddr) {
    struct ipip6_config *e = NULL;
    __u32 idx = 0;

    e = (struct ipip6_config *)bpf_map_lookup_elem(&ipip6_table, &idx);
    if (!e)
        return -1;

    memcpy(saddr, e->saddr, sizeof(e->saddr));
    memcpy(daddr, e->daddr, sizeof(e->daddr));

    return 0;
}  

static __always_inline int
get_br_iface_config(struct bridge_iface *e) {
    __u32 idx = 0;
    struct bridge_iface *conf;
    
    conf = (struct bridge_iface *)bpf_map_lookup_elem(&bridge_iface_conf, &idx);
    if (!conf)
        return -1;

    e->ipaddr = conf->ipaddr;
    memcpy(e->hwaddr, conf->hwaddr, 6);
    e->iface_idx = conf->iface_idx;

    return 0;
}  

#endif
