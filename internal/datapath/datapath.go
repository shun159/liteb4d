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
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/shun159/liteb4d/internal/bpf"
	"github.com/shun159/liteb4d/internal/logger"
)

type DatapathSpec struct {
	// interface config
	uplink UplinkConfig
	bridge BridgeConfig
	// ip6tnl spec
	ip6tnl *ip6Tunnel
	// bridge spec
	bridgeSpec *bridgeSpec
	// BPF links
	tcxLinks []link.Link
	// DNS forwader spec
	dnsForwarder *dnsForwarder
}

func Open(filename string) (*DatapathSpec, error) {
	logger.Info("datapath: opening datapath config: %s", filename)

	c, err := parseConfig(filename)
	if err != nil {
		logger.Error("open datapath: %s", err)
		return nil, fmt.Errorf("failed to open datapath: %s", err)
	}

	ds := &DatapathSpec{}
	ds.uplink = c.Uplink
	ds.bridge = c.Bridge
	ds.tcxLinks = make([]link.Link, 0)

	if err := ds.setupTcx(); err != nil {
		return nil, err
	}

	df, err := openDnsForwarder(ds.uplink.Iface, ds.bridge.Ipv4Addr)
	if err != nil {
		return nil, err
	}
	ds.dnsForwarder = df

	return ds, nil
}

func (dp *DatapathSpec) Close() error {
	for _, l := range dp.tcxLinks {
		if err := l.Close(); err != nil {
			logger.Error("close TCX links: %s", err)
			return fmt.Errorf("failed to close TCX link: %s", err)
		}
	}

	if err := dp.bridgeSpec.close(); err != nil {
		logger.Error("close bridge interface: %s", err)
		return fmt.Errorf("failed to close bridge interface: %s", err)
	}

	if err := dp.dnsForwarder.close(); err != nil {
		logger.Error("close DNS sockets: %s", err)
		return fmt.Errorf("failed to close DNS forwarder sockets", err)
	}

	return nil
}

// private functions

func (dp *DatapathSpec) setupTcx() error {
	logger.Info("datapath: attaching tc programs for each interfaces")

	if err := bpf.LoadBPF(); err != nil {
		return fmt.Errorf("failed to open datapath: %s", err)
	}

	if err := dp.setupBridge(); err != nil {
		return err
	}

	if err := dp.setupGateway(); err != nil {
		return err
	}

	return nil
}

func (dp *DatapathSpec) setupBridge() error {
	logger.Info("datapath: setting up bridge config")

	bridge, err := createBridge(dp.bridge.Iface, dp.bridge.Member)
	if err != nil {
		return fmt.Errorf("failed to setup bridge interface: %s", err)
	}

	tunIfAttrs, err := bridge.waitForCreated()
	if err != nil {
		return fmt.Errorf("failed to setup pkt interface: %s", err)
	}

	if err := bridge.setAddress(dp.bridge.Ipv4Addr); err != nil {
		return fmt.Errorf("failed to setup pkt interface: %s", err)
	}

	if err := bridge.up(); err != nil {
		return fmt.Errorf("failed to activate pkt interface: %s", err)
	}

	iface, err := net.InterfaceByName(dp.bridge.Iface)
	if err != nil {
		return fmt.Errorf("failed to find bridge interface: %s", err)
	}

	if err := bpf.SetBridgeConfig(iface); err != nil {
		return fmt.Errorf("failed to update bridge interface config: %s", err)
	}

	bridge.macaddr = [6]uint8(tunIfAttrs.HardwareAddr)
	dp.bridgeSpec = bridge

	if l, err := bpf.AttachBridgeIn(dp.bridge.Iface); err != nil {
		return fmt.Errorf("failed to attach ingress TCX: %s", err)
	} else {
		logger.Info("datapath: attaching BPF program on %s", dp.bridge.Iface)
		dp.tcxLinks = append(dp.tcxLinks, l)
	}

	return nil
}

func (dp *DatapathSpec) setupGateway() error {
	logger.Info("datapath: setting up tunnel config")

	ip6tnl, err := createTunnel(dp.uplink.Iface)
	if err != nil {
		return err
	}
	dp.ip6tnl = ip6tnl

	if err := dp.ip6tnl.setAddress("192.0.0.2/29"); err != nil {
		return err
	}

	tin, err := bpf.AttachGwIn(dp.uplink.Iface)
	if err != nil {
		return fmt.Errorf("failed to attach ingress TCX: %s", err)
	}
	logger.Info("datapath: attaching ingress BPF program on %s", dp.uplink.Iface)
	dp.tcxLinks = append(dp.tcxLinks, tin)

	return nil
}
