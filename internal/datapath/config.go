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
	"encoding/json"
	"fmt"
	"os"
)

type UplinkConfig struct {
	Iface string `json:"interface"`
}

type BridgeConfig struct {
	Iface    string   `json:"interface"`
	Ipv4Addr string   `json:"ipv4_address"`
	Member   []string `json:"member"`
}

type DatapathConfig struct {
	Uplink UplinkConfig `json:"uplink"`
	Bridge BridgeConfig `json:"bridge"`
}

func parseConfig(filename string) (*DatapathConfig, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file: %s", err)
	}

	var c DatapathConfig
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %s", err)
	}

	return &c, nil
}
