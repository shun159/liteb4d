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
	"context"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/godbus/dbus"
	"github.com/iguanesolutions/go-systemd/v5/resolved"
	"github.com/shun159/liteb4d/internal/logger"
)

var (
	dbusObjectResolve = "org.freedesktop.resolve1"
	dbusDnsProperty   = "org.freedesktop.resolve1.Link.DNS"
	bufSz             = 1024
)

type dnsForwarder struct {
	forwarders []net.IP
	udpSk      *net.UDPConn
	tcpSk      *net.TCPListener
}

// openDnsForwarder initializes a new dnsForwarder instance for the specified interface,
// sets up DNS servers, and starts UDP and TCP servers.
func openDnsForwarder(ifname string, laddr string) (*dnsForwarder, error) {
	df := new(dnsForwarder)
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("failed to find uplink interface %s: %s", ifname, err)
	}

	fwdAddrs, err := findDNSServerOnUplink(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to find DNS servers from systemd: %s", err)
	}

	laddr = strings.Split(laddr, "/")[0]
	df.forwarders = fwdAddrs

	if err := df.serveUdpServer(laddr); err != nil {
		return nil, fmt.Errorf("failed to serve UDP service: %s", err)
	}

	if err := df.serveTcpServer(laddr); err != nil {
		return nil, fmt.Errorf("failed to serve UDP service: %s", err)
	}

	return df, nil
}

// serveTcpServer sets up and starts the TCP server for handling DNS queries,
// listens on port 53, and spawns a goroutine to handle each connection.
func (df *dnsForwarder) serveTcpServer(laddr string) error {
	tcpAddr, err := net.ResolveTCPAddr("tcp", laddr+":53")
	if err != nil {
		return fmt.Errorf("failed to resolve TCP addr: %s", err)
	}

	tsk, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		return fmt.Errorf("failed to open TCP socket for DNS forwarder: %s", err)
	}
	df.tcpSk = tsk

	go func() {
		for {
			c, err := tsk.AcceptTCP()
			if err != nil {
				continue
			}
			go df.handleTcpConn(c)
		}
	}()

	return nil
}

// serveUdpServer sets up and starts the UDP server for handling DNS queries,
// listens on port 53, and continuously reads and responds to incoming packets.
func (df *dnsForwarder) serveUdpServer(laddr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", laddr+":53")
	if err != nil {
		return fmt.Errorf("failed to resolve UDP addr: %s", err)
	}

	usk, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("failed to open UDP socket for DNS forwarder: %s", err)
	}
	df.udpSk = usk

	go func() {
		for {
			buf := make([]byte, bufSz)
			n, addr, err := usk.ReadFrom(buf)
			if err != nil {
				continue
			}
			respBytes := df.handleUdpQuery(buf[:n])
			usk.WriteTo(respBytes, addr)
		}
	}()

	return nil
}

// handleTcpConn reads from and responds to each incoming TCP connection
// with the DNS query forwarded to a selected DNS server.
func (df *dnsForwarder) handleTcpConn(conn *net.TCPConn) error {
	for {
		buf := make([]byte, bufSz)
		n, err := conn.Read(buf)
		if err != nil {
			continue
		}
		respBytes := df.handleTcpQuery(buf[:n])
		conn.Write(respBytes)
	}
}

// close shuts down the open UDP and TCP sockets of the dnsForwarder.
func (df *dnsForwarder) close() error {
	if err := df.udpSk.Close(); err != nil {
		return fmt.Errorf("failed to close UDP socket: %s", err)
	}

	if err := df.tcpSk.Close(); err != nil {
		return fmt.Errorf("failed to close TCP socket: %s", err)
	}

	return nil
}

// handleUdpQuery forwards the received UDP DNS query to a selected DNS server
// and returns the response.
func (df *dnsForwarder) handleUdpQuery(b []byte) []byte {
	randFwdSrv := df.forwarders[rand.Intn(len(df.forwarders))]
	udpAddr := net.UDPAddr{randFwdSrv, 53, ""}
	fwdConn, err := net.DialTimeout("udp", udpAddr.String(), 3*time.Second)
	if err != nil {
		logger.Warn("failed to dial forwader's address: %s: %s", randFwdSrv, err)
		return nil
	}

	if _, err := fwdConn.Write(b); err != nil {
		logger.Warn("failed to write to forwarder sock: %s", err)
		return nil
	}

	buf := make([]byte, bufSz)
	n, err := fwdConn.Read(buf)
	if err != nil {
		logger.Warn("failed to read from forwarder sock: %s", err)
		return nil
	}

	return buf[:n]
}

// handleTcpQuery forwards the received TCP DNS query to a selected DNS server
// and returns the response.
func (df *dnsForwarder) handleTcpQuery(b []byte) []byte {
	randFwdSrv := df.forwarders[rand.Intn(len(df.forwarders))]
	tcpAddr := net.TCPAddr{randFwdSrv, 53, ""}
	fwdConn, err := net.DialTimeout("tcp", tcpAddr.String(), 3*time.Second)
	if err != nil {
		logger.Warn("failed to dial forwader's address: %s: %s", randFwdSrv, err)
		return nil
	}

	if _, err := fwdConn.Write(b); err != nil {
		logger.Warn("failed to write to forwarder sock: %s", err)
		return nil
	}

	buf := make([]byte, bufSz)
	n, err := fwdConn.Read(buf)
	if err != nil {
		logger.Warn("failed to read from forwarder sock: %s", err)
		return nil
	}

	return buf[:n]
}

// findDNSServerOnUplink queries systemd's resolved service via D-Bus to find DNS servers
// associated with the given network interface.
func findDNSServerOnUplink(iface *net.Interface) ([]net.IP, error) {
	ctx, cancelCtx := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelCtx()

	ifidx := iface.Index
	c, err := resolved.NewConn()
	if err != nil {
		return nil, err
	}
	defer c.Close()

	path, err := c.GetLink(ctx, ifidx)
	if err != nil {
		return nil, err
	}

	conn, err := dbus.SystemBus()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	objectManager := conn.Object(dbusObjectResolve, dbus.ObjectPath(path))
	variant, err := objectManager.GetProperty(dbusDnsProperty)
	if err != nil {
		return nil, err
	}

	addrs := []net.IP{}
	data := variant.Value().([][]interface{})
	for _, e := range data {
		b := e[1].([]byte)
		if len(b) != 16 {
			return nil, err
		}
		addrs = append(addrs, net.IP(b))
	}
	return addrs, nil
}
