package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os/exec"
	"sort"
)

/**** lldpcli command interface *******************************************************/
func run_lldpcli_show(arg string) ([]byte, error) {
	var res []byte
	var err error
	cmd := exec.Command("lldpcli", "-f", "json", "show", arg)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	res = stdout.Bytes()

	if len(stderr.Bytes()) > 0 {
		log.Println("lldpcli said on stderr:", stderr.String())
	}

	if exitError, ok := err.(*exec.ExitError); ok {
		return nil, fmt.Errorf("lldpcli returned nonzero exit code %d", exitError.ExitCode())
	}

    return res, err
}

/**** JSON Data structures ************************************************************/
// These were automatically converted from lldpcli JSON output to Go using
// https://mholt.github.io/json-to-go/ and then manually pieced apart
// into substructures.

type LldpcliChassisMember struct {
	ID struct {
		Type  string             `json:"type,omitempty"`
		Value string             `json:"value,omitempty"`
	}                            `json:"id,omitempty"`
	Descr      string            `json:"descr,omitempty"`
	// this is sometimes an array, sometimes a string... declare as interface{}
	// and fix further down
	MgmtIP     interface{}       `json:"mgmt-ip,omitempty"`
	Capability []struct {
		Type    string           `json:"type,omitempty"`
		Enabled bool             `json:"enabled,omitempty"`
	}                            `json:"capability,omitempty"`
}

// lldpcli JSON for any chassis consists of an object keyed by the system
// hostname with the machine chassis as only element in the object
type LldpcliChassisMap map[string]LldpcliChassisMember

type LldpcliChassisInfo struct {
	LocalChassis struct {
		// see comment for LldpcliNeighborInfo.Lldp
		Chassis json.RawMessage  `json:"chassis,omitempty"`
	}                            `json:"local-chassis,omitempty"`
}

type LldpcliNeighborPortID struct {
	Type  string                 `json:"type,omitempty"`
	Value string                 `json:"value,omitempty"`
}

type LldpcliNeighborPort struct {
	ID    LldpcliNeighborPortID  `json:"id,omitempty"`
	Descr string                 `json:"descr,omitempty"`
	TTL   string                 `json:"ttl,omitempty"`
}

type LldpcliNeighborInterface struct {
	Via     string               `json:"via,omitempty"`
	Rid     string               `json:"rid,omitempty"`
	Age     string               `json:"age,omitempty"`
	Chassis LldpcliChassisMap    `json:"chassis,omitempty"`
	Port    LldpcliNeighborPort  `json:"port,omitempty"`
}

type LldpcliNeighborInfo struct {
	// "lldp" here is the protocol name over which the information is received.
	// Since we don't currently support any other discovery protocols
	// implemented by lldpd, it is hardcoded here.
	Lldp struct {
		// This part of lldpcli -f json output is really weird: it produces an
		// array if multiple neighbors are found and only the object if there's
		// only one. It also makes fairly unnecessary use of encapsulated
		// objects. It gets fixed further down, immediately upon handling the
		// incoming JSON document.
		Interface json.RawMessage `json:"interface"`
	}                             `json:"lldp,omitempty"`
}

// Map for interface name -> neighbours found on that interface
type LldpcliNeighborInterfaceMap map[string]*LldpcliNeighborInterface

/**** JSON Parsing and handling of format weirdnesses *********************************/
// Because the MgmtIP field can be either an array of IP addresses in case of
// multiple reported addresses, or a string in case there is only one, it needs
// special treatment. Here it gets turned into a []string.
func (chassis *LldpcliChassisMember) fix_mgmt_ip() {
	switch vv := (*chassis).MgmtIP.(type) {
	case string: // transform into slice
		(*chassis).MgmtIP = []string{ vv }
	case []string: // it already is a slice
		break
	case []interface{}: // now these should be strings, assert
		ips := make([]string, len(vv))
		for i, v := range vv {
			switch v1 := v.(type) {
			case string:
				ips[i] = v1
			default:
				log.Printf("MgmtIP expected string, has datatype: %T, %s", v1, v1);
			}
		}
		(*chassis).MgmtIP = ips
		break
	case nil:
		(*chassis).MgmtIP = []string{}
		break
	default: // this shouldn't happen since interface{} supposedly handles all types
		log.Printf("Error: this code should be unreachable. Got %T instead of string-ish type", vv)
		(*chassis).MgmtIP = []string{}
	}

	// Sort IP addresses in ascending order to get more predictable results
	ips := (*chassis).MgmtIP.([]string)
	sort.Strings(ips)
	(*chassis).MgmtIP = ips
}

// Returns the type of Chassis ID.
func (chassis *LldpcliChassisMember) get_idtype() (idtype IdentifierType) {
	idtype, ok := _id_map[chassis.ID.Type]
	if !ok {idtype = UNKNOWN_ID}
	return
}

// Picks the most suitable Management IP from a list according to policy set by
// command line parameters
func get_suitable_mgmt_ip(MgmtIPs []string) (string, error) {
	if len(MgmtIPs) < 1 {
		return "", fmt.Errorf("no IP address found for Neighbor (is it defined?)")
	}

	// For machines that have Link Local/IPv6 MgmtIPs available, prefer those
	// over any other type of address returned by lldpd, depending on argv
	if ARGV.prefer_link_local || ARGV.prefer_ipv6 {
		for _, v := range MgmtIPs {
			ip := net.ParseIP(v)
			if ARGV.prefer_link_local && ip.IsLinkLocalUnicast() {
				return v, nil
			} else if ip.To4() == nil {
				return v, nil
			}
		}
	}

	// No link local address was found (or link local addresses aren't
	// preferred), return the first address
	return MgmtIPs[0], nil
}

// parses "lldpcli -f json show chassis" output
func lldp_parse_chassis_data(b []byte) (ret LocalChassis, err error) {
	// Step 1: unmarshal into temporary struct
	var ci LldpcliChassisInfo
	if err = json.Unmarshal(b, &ci); err != nil {return}

	// Step 2: try to unmarshal into LldpcliChassisMap
	var cm LldpcliChassisMap
	if err = json.Unmarshal(ci.LocalChassis.Chassis, &cm); err != nil {
		// that didn't work, create new LldpcliChassisMap with single element keyed by
		// empty string... in case lldpcli output is going crazy again
		log.Println("lldpcli chassis information has weird format - is lldpd running?")
		var c LldpcliChassisMember
		if err = json.Unmarshal(ci.LocalChassis.Chassis, &c); err != nil {return}
		cm = make(LldpcliChassisMap)
		cm[""] = c
	}

	// Step 3: fix all managment IPs found in chassis
	if len(cm) != 1 {
		log.Printf("lldpcli show chassis returns %d chassises, expected 1", len(cm))
	}
	for hostname, chassis := range cm {
		chassis.fix_mgmt_ip()

		ret = LocalChassis{
			Identifier:    chassis.ID.Value,
			IdType:        chassis.get_idtype(),
			Descr:         chassis.Descr,
			Hostname:      hostname,
			MgmtIPs:       chassis.MgmtIP.([]string),
		}
		break
	}

	return
}

type IdentifierType int

const (
	UNKNOWN_ID IdentifierType = iota
	MAC_ID
	LOCAL_ID
)

var _id_map = map[string]IdentifierType{
	"mac":     MAC_ID,
	"local":   LOCAL_ID,
	"unknown": UNKNOWN_ID,
}

func (t IdentifierType) String() string {
	return []string{"unknown", "mac", "local"}[t]
}

func (t IdentifierType) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

func (t *IdentifierType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	v, ok := _id_map[s]
	if !ok {
		*t = UNKNOWN_ID
		return fmt.Errorf("%q is not a valid identifier type", s)
	}
	*t = v
	return nil
}

// Contains the same information as LldpcliNeighborInfo but sensibly flattened
type Neighbor struct {
	Identifier         string            `json:"Identifier"`      // Unique identifier used by this machine (typically MAC address)
	IdType             IdentifierType    `json:"IdentifierType"`  // Type of Identifier field (MAC, LOCAL, UNKNOWN)
	Descr              string            `json:"Description"`     // Description (uname output unless altered by config file)
	Hostname           string            `json:"Hostname"`        // Hostname (e.g. DC3500 something)
	SourceIface        string            `json:"-"`               // Interface name on which this neighbor was found by the neighbor reporting it
	SourceNeighbor     string            `json:"-"`               // Primary MgmtIP address of neighbor which found this neighbor via LLDP
	MgmtIPs          []string            `json:"MgmtIPs"`         // Management IPs of this neighbor reported by LLDP
	PortState          PortToStateMap    `json:"STPPortState"`    // STP port state as reported by this neighbor
}

// For the local chassis, the data is almost the same, except SourceIface and
// potentially some other fields are unset.  Create a cheap type alias to make
// the difference more obvious on the type system level.
type LocalChassis Neighbor

// Declare a type alias to define methods on it later
type NeighborSlice []Neighbor

// There should only ever be one element in this map, and not all data is
// actually used, so it gets flattened to our saner Neighbor type here
func lldpcli_neighbor_interface_map_to_neighbor(host string, ifmap LldpcliNeighborInterfaceMap) (res Neighbor) {
	if len(ifmap) != 1 {
		// In this case, only the first one survives and the rest is
		// thrown away. Should this ever happen, investigate why.
		log.Printf("Incorrect number of interfaces in JSON object - possible bug, is this really lldpcli output?")
	}

	/* sourceIface: interface name ("eth0" etc),
	   neighborIface: struct LldpcliNeighborInterface */
	for sourceIface, neighborIface := range ifmap {
		var chassis     LldpcliChassisMember
		var chassisName string

		for chassisName, chassis = range neighborIface.Chassis {
			/* All MgmtIPs of type interface{} need to be coerced to []string */
			chassis.fix_mgmt_ip()
			break
		}

		res = Neighbor{
			SourceIface:    sourceIface,
			SourceNeighbor: host,
			Hostname:       chassisName,
			Identifier:     chassis.ID.Value,
			IdType:         chassis.get_idtype(),
			Descr:          chassis.Descr,
			MgmtIPs:        chassis.MgmtIP.([]string),
		// FIXME include neighborIface.Port (i.e. the remote port) in the data
		// structure if desirable later
		}
		res.ValidateHostname()
		return
	}
	return
}

// parses "lldpcli -f json show neighbors" output
func parse_lldpcli_neighbors_output(host string, b []byte) (NeighborSlice, error) {
	// First pass: Unmarshal { "lldp": ...data }
	var ln LldpcliNeighborInfo
	if err := json.Unmarshal(b, &ln); err != nil {
		return nil, err
	}

	// Second pass: Attempt to Unmarshal single Object returned for "interface"
	// in { "lldp": { "interface" : { "eth0" : <NeighborInterface> } } }
	var lm       LldpcliNeighborInterfaceMap
	var inputs []LldpcliNeighborInterfaceMap

	if err := json.Unmarshal(ln.Lldp.Interface, &lm); err == nil {
		inputs = []LldpcliNeighborInterfaceMap{ lm }

	// If this didn't work: attempt to unmarshal the same thing as an array of such
	// objects rather than a single object. lldpcli confusingly returns an array
	// only if there is more than one object:
	// { "lldp": { "interface": [
	//   { "eth0" : <NeighborInterface> },
	//   { "eth1" : <NeighborInterface> } ] } }
	} else if err := json.Unmarshal(ln.Lldp.Interface, &inputs); err != nil {
		return nil, fmt.Errorf("cannot unmarshal json object of unknown format: %s", ln.Lldp)
	}

	// Since the JSON format is crazy, reshape the returned data to be easier to
	// work with
	ifaces := make(NeighborSlice, len(inputs))

	/* loop over array of interface objects which have 1 element each such as
	   [{"eth0": <NeighborInterface>}, {"eth1": <NeighborInterface>}]
	   this is bad enough in JSON, but in Go each of these objects is
	   Unmarshaled into a map of length 1 */
	for i, ifmap := range inputs {
		ifaces[i] = lldpcli_neighbor_interface_map_to_neighbor(host, ifmap)
	}

	return ifaces, nil
}

/**** struct Neighbor receiver functions **********************************************/
// Validates hostname prefix for neighbors received via LLDP to make sure the
// network does not contain any rogue elements
func (n *Neighbor) ValidateHostname() {
	if !(ARGV.host_prefix <= (*n).Hostname) {
        log.Printf("Found machine '%s' which is seemingly not a %s: %+v", n.Identifier,
            ARGV.host_prefix, n)
	}
}

// Checks whether or not this neighbor has been initialized with data
func (n Neighbor) IsEmpty() bool {
	return n.Descr == "" &&
		n.Hostname == "" &&
		n.IdType == UNKNOWN_ID &&
		n.Identifier == "" &&
		n.SourceIface == "" &&
		len(n.MgmtIPs) == 0
}

/**** NeighborSlice receiver functions ************************************************/
// Returns a map from MgmtIP to hostname reported via LLDP
func (ns *NeighborSlice) get_hostnames() (res map[string]string) {
	res = make(map[string]string, len(*ns))
	for _, n := range *ns {
		mgmt_ip, err := get_suitable_mgmt_ip(n.MgmtIPs)
		if err != nil {
			log.Printf("Error getting MgmtIP from host %+v: %s", n, err)
		}
		res[mgmt_ip] = n.Hostname
	}
	return
}

// Returns a slice of one MgmtIP per host for a slice of Neighbor structs
func (ns *NeighborSlice) get_mgmt_ips() (res []string) {
	res = make([]string, len(*ns))
	for i, n := range *ns {
		mgmt_ip, err := get_suitable_mgmt_ip(n.MgmtIPs)
		if err != nil {
			log.Printf("Error getting MgmtIP from host %+v: %s", n, err)
		}
		res[i] = mgmt_ip
	}
	return
}

// Retrieves STP information for all neighbors in the slice
func (ns *NeighborSlice) gather_stp_states() {
    for i, n := range *ns {
        n.gather_node_stp_state()
        (*ns)[i] = n
    }
}

// Given a primary MgmtIP address, return the Neighbor
func (ns *NeighborSlice) find_neighbor_by_ip(ip string) (Neighbor, bool) {
	for _, n := range *ns {
		for _, mip := range n.MgmtIPs {
			if mip == ip {
				return n, true
			}
		}
	}
	return Neighbor{}, false
}

// Returns the parsed output from local "lldpcli show neighbors"
func get_local_neighbors() (ns NeighborSlice, err error) {
	bytes, err := run_lldpcli_show("neighbors")
	if err != nil {return}
	// LOCAL in all caps is used here to signify that this information didn't
	// come from the network but from locally run lldpcli
	// TODO replace by local identifier from lldp chassis
	ns, err = parse_lldpcli_neighbors_output("LOCAL", bytes)
	return
}

// Returns the MgmtIP from local "lldpcli show chassis"
func get_local_chassis_mgmt_ip() (mgmtIP string, err error) {
	bytes, err := run_lldpcli_show("chassis")
	if err != nil {return}
	chassis, err := lldp_parse_chassis_data(bytes)
	if err != nil {return}
	mgmtIP, err = get_suitable_mgmt_ip(chassis.MgmtIPs)
	return
}

// Compare a set of neighbors to another set of neighbors (peers) and return the
// set of peers which are expected and present (quiescent), excess as well as
// the set of missing peers
func (neighbors NeighborSlice) Compare(peers NeighborSlice) (quiescent NeighborSlice, excess NeighborSlice, missing NeighborSlice) {
	seen := make(map[string]bool, len(neighbors))

	// Step 1: set all IPs from neighbors to false in the map
	for _, n := range neighbors {
		ip, err := get_suitable_mgmt_ip(n.MgmtIPs)
		if err != nil {
			log.Printf("Error getting MgmtIP from Neighbor %+v: %s", n, err)
			continue
		}
		seen[ip] = false
	}

	// Step 2: for all IPs from peers, if they weren't in neighbors add them to
	// the list of excess IPs. Set the intersection of peers and neighbors to
	// true in the map, and add them to to_check for Step 4.
	var to_check NeighborSlice
	for _, n := range peers {
		// FIXME rather than get_suitable_management_ips here the check should be
		// whether or not the IP address is contained in MgmtIPs
		ip, err := get_suitable_mgmt_ip(n.MgmtIPs)
		if err != nil {
			log.Printf("Error getting MgmtIP from Neighbor %+v: %s", n, err)
			continue
		}
		if _, exists := seen[ip]; !exists {
			excess = append(excess, n)
		} else {
			to_check = append(to_check, n)
		}
		seen[ip] = true
	}

	// Step 3: loop over the map, adding all elements that are not in the
	// intersection (i.e. still set to false) to missing.
	for ip, exists := range seen {
		if !exists {
			for _, n := range neighbors {
				// FIXME see above
				n_ip, err := get_suitable_mgmt_ip(n.MgmtIPs)
				if err != nil {
					log.Printf("Error getting MgmtIP from Neighbor %+v: %s", n, err)
					continue // XXX add error
				}
				if ip == n_ip {
					missing = append(missing, n)
					break
				}
			}
		}
	}

	// FIXME TODO Step 4: add IPs which are found but whose characteristics do
	// not match to missing, with information about the mismatch.
	quiescent = to_check

	return
}
