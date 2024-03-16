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

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

func AttachGwIn(ifname string) (link.Link, error) {
	p, err := getGwIn()
	if err != nil {
		return nil, fmt.Errorf("failed to get gw_in program: %s", err)
	}

	if l, err := attachIn(p, ifname); err != nil {
		return nil, fmt.Errorf("failed to attach gw_in program: %s", err)
	} else {
		return l, nil
	}
}

func AttachBridgeIn(ifname string) (link.Link, error) {
	p, err := getBridgeIn()
	if err != nil {
		return nil, fmt.Errorf("failed to get pkt0_in program: %s", err)
	}

	if l, err := attachIn(p, ifname); err != nil {
		return nil, fmt.Errorf("failed to attach pkt0_in program: %s", err)
	} else {
		return l, nil
	}
}

// internal functions

func attachIn(p *ebpf.Program, ifname string) (link.Link, error) {
	if l, err := attachTcx(p, unix.BPF_TCX_INGRESS, ifname); err != nil {
		return nil, err
	} else {
		return l, nil
	}
}

func attachOut(p *ebpf.Program, ifname string) (link.Link, error) {
	if l, err := attachTcx(p, unix.BPF_TCX_EGRESS, ifname); err != nil {
		return nil, err
	} else {
		return l, nil
	}
}

func attachTcx(prog *ebpf.Program, attach uint32, ifname string) (link.Link, error) {
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("failed to attach TCX: %s", err)
	}

	tcxOptions := link.TCXOptions{
		Program:          prog,
		Attach:           ebpf.AttachType(attach),
		Interface:        iface.Index,
		ExpectedRevision: 0,
	}

	l, err := link.AttachTCX(tcxOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to attach TCX: %s", err)
	}

	return l, nil
}
