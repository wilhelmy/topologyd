package main
// This file is used to implement the STP related parts of the JSON API,
// wrapping all mstpd specific code into one file for ease of switching the
// underlying STP implementation.

import (
	//"fmt"
	"bytes"
	"log"
	"encoding/json"
	"os/exec"
)

// run mstpctl to extract information
func run_mstpctl(arg ...string) ([]byte, error) {
	args := []string{"-f", "json"}
	args = append(args, arg...)
	cmd := exec.Command("mstpctl", args...)

	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()

	return out.Bytes(), err
}

// Converted from mstpctl output
type MstpdPortState struct {
	Port             string `json:"port"`
	Bridge           string `json:"bridge"`
	PointToPoint     string `json:"point-to-point"`
	OperEdgePort     string `json:"oper-edge-port"`
	PortID           string `json:"port-id"`
	Enabled          string `json:"enabled"`
	State            string `json:"state"`
	Role             string `json:"role"`
	DesignatedBridge string `json:"designated-bridge"`
	DesignatedPort   string `json:"designated-port"`
	DesignatedRoot   string `json:"designated-root"`
}


// Get JSON output from running e.g. "mstpctl -f json showport br0"
func Mstpd_get_port_state(bridge_if string) (ret []byte, err error) {
	ret, err = run_mstpctl("showport", bridge_if)
	return
}

// Read command output into the struct specified above
func Mstpd_parse_port_state(in []byte) (ret []MstpdPortState, err error) {
	err = json.Unmarshal(in, &ret)
	return
}

type PortToStateMap map[string]string

// Format Mstpd_parse_port_state result into mstpd independent JSON format
func STP_get_port_state_json(bridge_if string) (ret []byte) {
	mjson, err := Mstpd_get_port_state(bridge_if)
	if err != nil {log.Printf("mstpd json response error: %s", err); return}

	ports, err := Mstpd_parse_port_state(mjson)
	if err != nil {log.Printf("mstpd json response parse error: %s", err); return}

	pmap := make(PortToStateMap)
	for _, v := range ports {
		pmap[v.Port] = "unknown"

		switch (v.State) {
		// these are acceptable values
		case "unknown", "discarding", "learning", "forwarding":

		// this shouldn't happen
		default:
			log.Printf("BUG: mstpd port state reported %s, should be one of "+
				"{unknown,discarding,learning,forwarding}.", v.State)
			continue
		}
		pmap[v.Port] = v.State
	}

	ret, err = json.Marshal(pmap)
	if err != nil {log.Printf("mstpd json marshaling error: %s", err); return}

	return
}

func STP_parse_port_state_json(in []byte) (ret PortToStateMap) {
	err := json.Unmarshal(in, &ret)
	if err != nil {log.Printf("STP json response error: %s", err)}
	return
}
