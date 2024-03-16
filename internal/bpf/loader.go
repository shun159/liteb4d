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

	"github.com/cilium/ebpf"
)

var objs *datapathObjects
var maps *datapathMaps
var prog *datapathPrograms

func LoadBPF() error {
	objs = &datapathObjects{}
	if err := loadDatapathObjects(objs, nil); err != nil {
		return err
	}

	maps = &objs.datapathMaps
	prog = &objs.datapathPrograms

	return nil
}

// internal functions

func getGwIn() (*ebpf.Program, error) {
	p, err := getProgram()
	if err != nil {
		return nil, fmt.Errorf("failed to load gw_in: %s", err)
	}
	return p.GatewayPacketIn, nil
}

func getBridgeIn() (*ebpf.Program, error) {
	p, err := getProgram()
	if err != nil {
		return nil, fmt.Errorf("failed to load pkt0_in: %s", err)
	}
	return p.BridgePacketIn, nil
}

func getIpip6Config() (*ebpf.Map, error) {
	m, err := getMap()
	if err != nil {
		return nil, fmt.Errorf("failed to load ipip6_table: %s", err)
	}
	return m.Ipip6Table, nil
}

func getBridgeConfig() (*ebpf.Map, error) {
	m, err := getMap()
	if err != nil {
		return nil, fmt.Errorf("failed to load bridge_config map: %s", err)
	}
	return m.BridgeIfaceConf, nil
}

func getMap() (*datapathMaps, error) {
	if maps == nil {
		return nil, fmt.Errorf("BPF maps is not loaded")
	}
	return maps, nil
}

func getProgram() (*datapathPrograms, error) {
	if prog == nil {
		return nil, fmt.Errorf("program is not initialized")
	}
	return prog, nil
}
