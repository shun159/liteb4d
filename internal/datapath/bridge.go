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

package datapath

import (
	"fmt"
	"time"

	"github.com/shun159/liteb4d/internal/logger"
	"github.com/vishvananda/netlink"
)

type bridgeSpec struct {
	iface         *netlink.Bridge
	member        []string
	linkUpdate    chan netlink.LinkUpdate
	linkEmptyChan chan struct{}
	ifindex       int
	macaddr       [6]uint8
}

func createBridge(name string, members []string) (*bridgeSpec, error) {
	logger.Info("datapath/bridge: creating bridge %s that has %d member", name, len(members))

	bridge := &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: name}}
	if err := netlink.LinkAdd(bridge); err != nil {
		return nil, fmt.Errorf("failed to create bridge: %s: %s", name, err)
	}

	for _, ifname := range members {
		ifaceAttr := &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: ifname}}
		if err := netlink.LinkSetMaster(ifaceAttr, bridge); err != nil {
			return nil, fmt.Errorf("failed to add member to the bridge: %s: %s", ifname, err)
		}
	}

	bs := new(bridgeSpec)
	bs.iface = bridge
	bs.member = members
	bs.linkEmptyChan = make(chan struct{})
	bs.linkUpdate = make(chan netlink.LinkUpdate)

	return bs, nil
}

func (bs *bridgeSpec) up() error {
	logger.Info("datapath/bridge: bringing up bridge interface")
	return netlink.LinkSetUp(bs.iface)
}

func (bs *bridgeSpec) close() error {
	logger.Info("datapath/bridge: closing bridge interface")
	return netlink.LinkDel(bs.iface)
}

func (bs *bridgeSpec) setAddress(s string) error {
	logger.Info("datapath/bridge: setting address: %s for bridge %s", s, bs.iface.Name)

	addr, err := netlink.ParseAddr(s)
	if err != nil {
		return fmt.Errorf("failed to parse ipv4 address: %s: %s", s, err)
	}

	if err := netlink.AddrAdd(bs.iface, addr); err != nil {
		return fmt.Errorf("failed to set addr: %s to bridge iface: %s", s, err)
	}

	return nil
}

func (bs *bridgeSpec) waitForCreated() (*netlink.LinkAttrs, error) {
	if err := netlink.LinkSubscribe(bs.linkUpdate, bs.linkEmptyChan); err != nil {
		return nil, fmt.Errorf("failed to subscribe channel: %s", err)
	}

	for {
		select {
		case update := <-bs.linkUpdate:
			if update.Attrs().Name == bs.iface.Name {
				return update.Attrs(), nil
			}
		case <-time.After(10 * time.Second):
			return nil, fmt.Errorf("failed to receive link update in a deadline")
		}
	}
}
