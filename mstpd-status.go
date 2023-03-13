package main
// This file is used to implement the STP related parts of the JSON API,
// wrapping all mstpd specific code into one file for ease of switching the
// underlying STP implementation.

import (
	"fmt"
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
type MstpdShowportResult struct {
	Port             string     `json:"port"`
	Bridge           string     `json:"bridge"`
	PointToPoint     string     `json:"point-to-point"`
	OperEdgePort     string     `json:"oper-edge-port"`
	PortID           string     `json:"port-id"`
	Enabled          string     `json:"enabled"`
	State            PortState  `json:"state"`
	Role             string     `json:"role"`
	DesignatedBridge string     `json:"designated-bridge"`
	DesignatedPort   string     `json:"designated-port"`
	DesignatedRoot   string     `json:"designated-root"`
}


// Get JSON output from running e.g. "mstpctl -f json showport br0"
func mstpd_get_showport_result(bridge_if string) (ret []byte, err error) {
	ret, err = run_mstpctl("showport", bridge_if)
	return
}

// Read command output into the struct specified above
func mstpd_parse_showport_result(in []byte) (ret []MstpdShowportResult, err error) {
	err = json.Unmarshal(in, &ret)
	return
}

type PortState int
const (
	Unknown PortState = iota
	Discarding
	Learning
	Forwarding
)

var (
	portStateName = map[PortState]string {
		Unknown:    "unknown",
		Discarding: "discarding",
		Learning:   "learning",
		Forwarding: "forwarding",
	}
	portStateValue = map[string]PortState {
		"unknown":    Unknown,
		"discarding": Discarding,
		"learning":   Learning,
		"forwarding": Forwarding,
	}
)

// Convert PortState to String representation
func (p PortState) String() (s string) {
	s = portStateName[p]
	return
}

// Convert string to PortState representation
func ParsePortState(s string) (PortState, error) {
	value, ok := portStateValue[s]
	if !ok {
		return PortState(0),
			fmt.Errorf("%q is not a valid port state (one of: %v)",
			s, portStateValue)
	}
	return PortState(value), nil
}

func (p PortState) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}

func (p *PortState) UnmarshalJSON(data []byte) (err error) {
    var portState string
    if err := json.Unmarshal(data, &portState); err != nil {
        return err
    }
    if *p, err = ParsePortState(portState); err != nil {
        return err
    }
    return nil
}

func (p PortState) LinkColor() string {
	return [...]string{ "purple", "lightgray", "darkgreen", "black" }[p]
}

type PortToStateMap map[string]PortState

// Format Mstpd_parse_port_state result into mstpd independent JSON format
func STP_get_port_state_json(iface string) (ret []byte) {
	mjson, err := mstpd_get_showport_result(iface)
	if err != nil {log.Printf("mstpd json response error: %s", err); return}

	ports, err := mstpd_parse_showport_result(mjson)
	if err != nil {log.Printf("mstpd json response parse error: %s", err); return}

	pmap := make(PortToStateMap, len(ports))
	for _, v := range ports {
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
