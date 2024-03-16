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
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"time"

	"github.com/iguanesolutions/go-systemd/v5/resolved"
	"github.com/shun159/liteb4d/internal/bpf"
	"github.com/shun159/liteb4d/internal/logger"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"
	"golang.org/x/sys/unix"
)

type dsliteConfig struct {
	Aftr string `json:"aftr"`
}

type tunnelConfig struct {
	EnablerName string       `json:"enabler_name"`
	ServiceName string       `json:"service_name"`
	IspName     string       `json:"isp_name"`
	Ttl         int          `json:"ttl"`
	Order       []string     `json:"order"`
	Dslite      dsliteConfig `json:"dslite"`
}

// ip6Tunnel struct represents an IPv6 tunnel with fields for the uplink and DNS addresses.
type ip6Tunnel struct {
	uplinkAddr  net.IPNet
	aftrAddr    net.IP
	tunConfig   *tunnelConfig
	ip6tnlIface *netlink.Ip6tnl
}

func createTunnel(iface string) (*ip6Tunnel, error) {
	logger.Info("datapath/tunnel: setting up IPv6 tunnel on %s", iface)

	tnl := new(ip6Tunnel)

	if err := tnl.fetchIfaceAddr(iface); err != nil {
		logger.Info("datapath/tunnel: failed to fetch uplink addr: %s", err)
		if tnl.waitIfaceAddrSetup(iface); err != nil {
			return nil, err
		}
	}

	if err := tnl.resolveAftrAddr(iface); err != nil {
		logger.Error("datapath/tunnel: failed to fetch AFTR config: %s", err)
		return nil, err
	}

	if err := tnl.createIP6Tnl(); err != nil {
		logger.Error("datapath/tunnel: failed to create ip6tnl interface: %s", err)
		return nil, err
	}

	return tnl, nil
}

func (tnl *ip6Tunnel) setAddress(s string) error {
	logger.Info("datapath/bridge: setting address: %s for ip6tnl", s)

	if err := bpf.SetIPIP6Addrs(tnl.ip6tnlIface.Local, tnl.ip6tnlIface.Remote); err != nil {
		return fmt.Errorf("failed to update ipip6 address config: %s", err)
	}

	return nil
}

func (tnl *ip6Tunnel) createIP6Tnl() error {
	logger.Info("datapath/tunnel: creating ip6tnl interface "+
		" local: %s -> remote: %s", tnl.uplinkAddr.IP, tnl.aftrAddr)

	tnl.ip6tnlIface = &netlink.Ip6tnl{
		Local:      tnl.uplinkAddr.IP,
		Remote:     tnl.aftrAddr,
		EncapLimit: 0,
		EncapType:  0,
		LinkAttrs: netlink.LinkAttrs{
			Name:  "tc-ip6tnl",
			Flags: unix.IFF_POINTOPOINT,
		},
	}

	return nil
}

func (tnl *ip6Tunnel) resolveAftrAddr(name string) error {
	logger.Info("datapath/tunnel: attempting to resolve AFTR address")

	httpCli, err := httpClient()
	if err != nil {
		return err
	}

	// or if you don't have an http client you can call HTTPClient method on resolver
	// it comes with some nice default values.
	url, err := resolveConfigURL()
	if err != nil {
		return err
	}

	resp, err := httpCli.Get(url)
	if err != nil {
		return fmt.Errorf("fetch dslite config from %s: %s", url, err)
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("fetch dslite config from %s statusCode: %d", url, resp.StatusCode)
	}

	tconf := new(tunnelConfig)
	b, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(b, tconf); err != nil {
		return fmt.Errorf("parse response failed: %s", err)
	}

	logger.Info("datapath/tunnel: succeed to fetch AFTR config")
	logger.Info("enabler: %s "+
		"service: %s "+
		"ISP: %s "+
		"AFTR address: %s",
		tconf.EnablerName,
		tconf.ServiceName,
		tconf.IspName,
		tconf.Dslite.Aftr)

	tnl.tunConfig = tconf
	tnl.aftrAddr = net.ParseIP(tconf.Dslite.Aftr)

	return nil
}

// fetchAddr sets the uplink address of the ip6Tunnel to the IPv6 address of the given interface.
// Returns an error if it fails to fetch the address.
func (tnl *ip6Tunnel) fetchIfaceAddr(name string) error {
	var ifaceAddr *net.IPNet

	l, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}

	// Fetches IPv6 addresses associated with the link.
	addrs, err := netlink.AddrList(l, netlink.FAMILY_V6)
	if err != nil {
		return err
	}

	// Finds a non-link-local multicast IPv6 address and sets it as the interface address.
	for _, addr := range addrs {
		if addr.IP.IsGlobalUnicast() {
			ifaceAddr = addr.IPNet
			break
		}
	}

	// Returns an error if no IPv6 address is set on the interface.
	if ifaceAddr == nil {
		return fmt.Errorf("ipv6 address not set on %s", name)
	}

	logger.Info("datapath/tunnel: uplink address on %s is %s", name, ifaceAddr.IP)
	tnl.uplinkAddr = *ifaceAddr

	return nil
}

// waitAddrSetup waits for an IPv6 address to be set up on a given interface.
// If the address is not set up within a deadline, it returns an error.
func (tnl *ip6Tunnel) waitIfaceAddrSetup(name string) error {
	logger.Info("datapath/tunnel: waiting for setting up uplink address")

	iface, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("failed to find interface: %s", err)
	}

	ch := make(chan netlink.AddrUpdate)
	done := make(chan struct{})
	deadline := 10 * time.Second

	if err := netlink.AddrSubscribe(ch, done); err != nil {
		return fmt.Errorf("failed to setting up address subscriber: %s", err)
	}

	// Waits for an address update or the deadline to be exceeded.
	for {
		select {
		case update := <-ch:
			// Checks if the update is for the specified interface and fetches its address.
			if iface.Index == update.LinkIndex {
				return tnl.fetchIfaceAddr(name)
			}
		case <-time.After(deadline):
			// Returns an error if the deadline is exceeded without an address update.
			return fmt.Errorf("deadline exceeded for wating ipv6 addr on %s", name)
		}
	}
}

func httpClient() (*http.Client, error) {
	r, err := resolved.NewResolver()
	if err != nil {
		return nil, fmt.Errorf("create resolver for http client: %s", err)
	}

	// if you want to make a custom http client using systemd-resolved as resolver
	httpCli := &http.Client{
		Transport: &http.Transport{
			DialContext:     r.DialContext,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	return httpCli, nil
}

func resolveConfigURL() (string, error) {
	ctx, cancelCtx := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelCtx()

	var url string

	r, err := resolved.NewResolver()
	if err != nil {
		return url, fmt.Errorf("create resolver for http client: %s", err)
	}

	txtList, err := r.LookupTXT(ctx, "4over6.info")
	if err != nil {
		return url, err
	}

	if len(txtList) < 1 {
		return url, fmt.Errorf("resolve config URL: empty txt reponse")
	}

	reg := regexp.MustCompile(`url=(?P<path>(http[s]?:\/\/)?([^\/\s]+\/)(.*)) `)
	sub := reg.FindStringSubmatch(txtList[0])
	idx := reg.SubexpIndex("path")

	if len(sub) <= idx {
		return url, fmt.Errorf("resolve config URL: mismatch length")
	}

	return sub[idx], nil
}
