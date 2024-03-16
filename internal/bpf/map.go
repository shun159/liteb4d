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

package bpf

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func SetIPIP6Addrs(srcIP, dstIP net.IP) error {
	confm, err := getIpip6Config()
	if err != nil {
		return err
	}

	k := uint32(0)
	v := datapathIpip6Config{}
	v.Saddr = [16]uint8{}
	v.Daddr = [16]uint8{}

	for idx, b := range srcIP {
		v.Saddr[idx] = uint8(b)
	}
	for idx, b := range dstIP {
		v.Daddr[idx] = uint8(b)
	}

	return confm.Put(&k, &v)
}

func SetBridgeConfig(iface *net.Interface) error {
	iflink, err := netlink.LinkByName(iface.Name)
	if err != nil {
		return fmt.Errorf("failed to create ifl for %s: %s", iface.Name, err)
	}

	ipaddrs, err := netlink.AddrList(iflink, unix.AF_INET)
	if err != nil {
		return fmt.Errorf("failed to list ip addresses on %s: %s", iface.Name, err)
	}

	var ipAddr *net.IP
	for _, ipaddr := range ipaddrs {
		if ipaddr.IP.IsPrivate() {
			ipAddr = &ipaddr.IP
		}
	}

	if ipAddr == nil {
		return fmt.Errorf("failed to find private ip address on %s", iface.Name)
	}

	brconfm, err := getBridgeConfig()
	if err != nil {
		return err
	}

	k := uint32(0)
	v := datapathBridgeIface{}

	b := [4]uint32{}
	for idx, o := range *ipAddr {
		b[idx] = uint32(o)
	}
	v.Ipaddr = uint32((b[3] << 24) + (b[2] << 16) + (b[1] << 8) + b[0])

	v.Hwaddr = [6]uint8{}
	for idx, b := range iface.HardwareAddr {
		v.Hwaddr[idx] = uint8(b)
	}
	v.IfaceIdx = uint32(iface.Index)

	return brconfm.Put(&k, &v)
}

// private functions
