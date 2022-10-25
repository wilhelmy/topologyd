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
const dbg_read_json_from_file = true

func run_lldpcli_show(arg string) ([]byte, error) {
	var res []byte
	var err error

	if dbg_read_json_from_file { // i.e. for development purposes on x86 host
		res, err = os.ReadFile(fmt.Sprintf("./examples/lldpcli-show-%s.json", arg))

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
// https://mholt.github.io/json-to-go/

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

type NeighborInfo struct {
	Lldp struct {
		Interface []struct {
			En0 struct {
				Via     string `json:"via,omitempty"`
				Rid     string `json:"rid,omitempty"`
				Age     string `json:"age,omitempty"`
				Chassis struct {
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
				} `json:"chassis,omitempty"`
				Port struct {
					ID struct {
						Type  string `json:"type,omitempty"`
						Value string `json:"value,omitempty"`
					} `json:"id,omitempty"`
					Descr string `json:"descr,omitempty"`
					TTL   string `json:"ttl,omitempty"`
				} `json:"port,omitempty"`
			} `json:"en0,omitempty"`
			En1 struct {
				Via     string `json:"via,omitempty"`
				Rid     string `json:"rid,omitempty"`
				Age     string `json:"age,omitempty"`
				Chassis struct {
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
				} `json:"chassis,omitempty"`
				Port struct {
					ID struct {
						Type  string `json:"type,omitempty"`
						Value string `json:"value,omitempty"`
					} `json:"id,omitempty"`
					Descr string `json:"descr,omitempty"`
					TTL   string `json:"ttl,omitempty"`
				} `json:"port,omitempty"`
			} `json:"en1,omitempty"`
		} `json:"interface,omitempty"`
	} `json:"lldp,omitempty"`
}

func json_dbg(obj interface{}) {
	if dbg_json_verbose {
		log.Print("Re-Marshaled JSON: ")
		log.Println(json.Marshal(&obj))
	}
}

func lldp_chassis_data(b []byte) (*ChassisInfo, error) {
	var c ChassisInfo
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}

	json_dbg(c);
	return &c, nil;
}

func lldp_neighbor_data(b []byte) (*NeighborInfo, error) {
	var n NeighborInfo

	if err := json.Unmarshal(b, &n); err != nil {
		return nil, err
	}

	json_dbg(n);
	return &n, nil;
}
