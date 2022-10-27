package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"encoding/json"
)

const dbg_json_verbose = true
const dbg_read_json_from_file = false

func run_lldpcli_show(arg string) ([]byte, error) {
	var res []byte
	var err error

	if dbg_read_json_from_file { // i.e. for development purposes on x86 host
		fd, err := os.Open(fmt.Sprintf("./examples/lldpcli-show-%s.json", arg))
		if err != nil {return nil,err}
		res := make([]byte, 9999)
		_, err = fd.Read(res)
		if err != nil {return nil,err}
		fd.Close()


	} else {
		cmd := exec.Command("lldpcli", "-f", "json", "show", arg)

		var out bytes.Buffer
		cmd.Stdout = &out
		err = cmd.Run()
		res = out.Bytes()
	}

    return res, err
}

// JSON data structures are currently automatically converted to Go using
// https://mholt.github.io/json-to-go/ and then manually pieced apart
// into substructures.  The names dc3500, en0 and en1 are project specific and
// hardcoded due to limitations in the JSON API.

type ChassisInfo struct {
	LocalChassis struct {
		Chassis struct {
			Dc3500 struct {
				ID struct {
					Type  string `json:"type,omitempty"`
					Value string `json:"value,omitempty"`
				} `json:"id,omitempty"`
				Descr      string   `json:"descr,omitempty"`
				MgmtIP     []string `json:"mgmt-ip,omitempty"`
				Capability []struct {
					Type    string `json:"type,omitempty"`
					Enabled bool   `json:"enabled,omitempty"`
				} `json:"capability,omitempty"`
			} `json:"dc3500,omitempty"`
		} `json:"chassis,omitempty"`
	} `json:"local-chassis,omitempty"`
}

type NeighborChassis struct {
	Dc3500 struct {
		ID struct {
			Type  string `json:"type,omitempty"`
			Value string `json:"value,omitempty"`
		} `json:"id,omitempty"`
		Descr      string `json:"descr,omitempty"`
		MgmtIP     string `json:"mgmt-ip,omitempty"`
		Capability []struct {
			Type    string `json:"type,omitempty"`
			Enabled bool   `json:"enabled,omitempty"`
		} `json:"capability,omitempty"`
	} `json:"dc3500,omitempty"`
}
type NeighborPortID struct {
	Type  string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
}

type NeighborPort struct {
	ID    NeighborPortID `json:"id,omitempty"`
	Descr string         `json:"descr,omitempty"`
	TTL   string         `json:"ttl,omitempty"`
}

type NeighborInterface struct {
	Via     string          `json:"via,omitempty"`
	Rid     string          `json:"rid,omitempty"`
	Age     string          `json:"age,omitempty"`
	Chassis NeighborChassis `json:"chassis,omitempty"`
	Port    NeighborPort    `json:"port,omitempty"`
}

type NeighborInfo struct {
	Lldp struct {
		Interface []struct {
			// TODO: This part of lldpcli -f json output is slightly weird and
			// doesn't work well with go's json library, hence the hardcoded
			// interface names. Seems like -f json0 would avoid this. (But would
			// it avoid the hardcoded Dc3500 in NeighborChassis? Evaluate...)
			En0 *NeighborInterface  `json:"en0,omitempty"`
			En1 *NeighborInterface  `json:"en1,omitempty"`
		} `json:"interface,omitempty"`
	} `json:"lldp,omitempty"`
}

// conditionally log message to see if data parses correctly into the struct
func dbg_json(obj interface{}) {
	if dbg_json_verbose {
		json, err := json.Marshal(&obj)
		log.Print("Re-Marshaled JSON, error=", err, " -- ", string(json))
	}
}

// parses "lldpcli -f json show chassis" output
func lldp_parse_chassis_data(b []byte) (*ChassisInfo, error) {
	var c ChassisInfo
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}

	dbg_json(c)
	return &c, nil
}

// parses "lldpcli -f json show chassis" output, returns en0+en1 netif member
// struct as a slice
func lldp_parse_neighbor_data(b []byte) ([]NeighborInterface, error) {
	var n NeighborInfo

	if err := json.Unmarshal(b, &n); err != nil {
		return nil, err
	}

	dbg_json(n)

	var en0 *NeighborInterface = nil
	var en1 *NeighborInterface = nil

	if len(n.Lldp.Interface) > 0 {
		if n.Lldp.Interface[0].En0 != nil && n.Lldp.Interface[0].En1 != nil {
			return nil, fmt.Errorf("lldp_parse_neighbor_data: iface 0 is both en0 and en1")
		}
		en0 = n.Lldp.Interface[0].En0
		en1 = n.Lldp.Interface[0].En1
	}
	if len(n.Lldp.Interface) > 1 {
		if n.Lldp.Interface[1].En0 != nil && n.Lldp.Interface[1].En1 != nil {
			return nil, fmt.Errorf("lldp_parse_neighbor_data: iface 1 is both en0 and en1")
		}

		if en0 == nil { en0 = n.Lldp.Interface[1].En0 }
		if en1 == nil { en1 = n.Lldp.Interface[1].En1 }
	}

	ret := make([]NeighborInterface, 2)
	if en0 != nil { ret[0] = *en0 }
	if en1 != nil { ret[1] = *en1 }

	return ret, nil
}
