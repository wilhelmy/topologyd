package topologyD

// This file contains the the STP related parts of the JSON API, wrapping all
// mstpd specific code into one file for ease of switching the underlying STP
// implementation. The resulting JSON API queries the port state from mstpd,
// throwing away all excess information. It then serves a user-visible read-only
// API endpoint that provides a simple key-value object mapping port names to
// their STP state.

import (
	"fmt"
	"bytes"
	"log"
	"encoding/json"
	"os/exec"
)

// run mstpctl to extract information
// TODO(mw) triplicate code
func run_mstpctl(arg ...string) ([]byte, error) {
	args := []string{"-f", "json"}
	args = append(args, arg...)
	cmd := exec.Command("mstpctl", args...)

	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()

	return out.Bytes(), err
}

// struct MstpdShowportResult{} corresponds to "mstpctl -f json showport"
// command output.
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


// mstpd_get_showport_result() reads the JSON output from running a command such
// as "mstpctl -f json showport br0". «bridge_if» specifies which bridged
// interface to extract data from.
//
// Returns the data as byte slice «ret» if successful, or «err» otherwise.
func mstpd_get_showport_result(bridge_if string) (ret []byte, err error) {
	ret, err = run_mstpctl("showport", bridge_if)
	return
}

// mstpd_parse_showport_result() parses the command output of
// mstpd_get_showport_result() from the byte slice «in».
//
// Returns «ret» if successful, «err» otherwise.
func mstpd_parse_showport_result(in []byte) (ret []MstpdShowportResult, err error) {
	err = json.Unmarshal(in, &ret)
	return
}

// PortState is an enum type for the four different RSTP port states.
type PortState int
const (
	Unknown PortState = iota
	Discarding
	Learning
	Forwarding
)

// Mappings back and forward between the enum values for PortState and
// corresponding strings
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

// (PortState).String() converts PortState «p» to String representation.
//
// Returns string representation «s».
func (p PortState) String() (s string) {
	s = portStateName[p]
	return
}

// ParsePortState() converts string «s» to PortState enum representation.
//
// Returns PortState «p» on success and «err» on error.
func ParsePortState(s string) (p PortState, err error) {
	value, ok := portStateValue[s]
	if !ok {
		return PortState(0),
			fmt.Errorf("%q is not a valid port state (one of: %v)",
			s, portStateValue)
	}
	return PortState(value), nil
}

// (PortState).MarshalJSON() is the JSON marshaling function for the PortState
// type for interface json.Marshaler. It Marshals PortState «p» into a JSON byte
// slice.
//
// Returns «data» in case of success and «err» in case of error.
func (p PortState) MarshalJSON() (data []byte, err error) {
	return json.Marshal(p.String())
}

// (*PortState).UnmarshalJSON is the unmarshaling function for PortState type
// for interface json.Unmarshaler. Unmarshals a byte slice «data» into the
// PortState «p».
//
// Returns «err» on error.
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

// (PortState).LinkColor() returns a display color for the ethernet RSTP link
// state described by PortState «p» for use in graphviz or HTML.
func (p PortState) LinkColor() string {
	return [...]string{ "purple", "lightgray", "darkgreen", "black" }[p]
}

// A map type alias to map from the interface name of a network port to the STP
// port state of that port
type PortToStateMap map[string]PortState

// stp_get_port_state_json() formats mstpd_parse_port_state() result on bridge
// interface «iface» into a portable JSON format which maps interface names to
// RSTP port states. Logs errors internally.
//
// Returns «ret» as byte slice ready for serving via HTTP, or an empty slice on
// error.
//
// Example JSON:
//   {"en0": "discarding", "en1": "forwarding"}
func stp_get_port_state_json(iface string) (ret []byte) {
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

// stp_parse_port_state_json() parses the byte slice «in», logging errors
// internally.
//
// Returns result as «ret», or nil on error.
func stp_parse_port_state_json(in []byte) (ret PortToStateMap) {
	err := json.Unmarshal(in, &ret)
	if err != nil {log.Printf("STP json response error: %s", err)}
	return
}
