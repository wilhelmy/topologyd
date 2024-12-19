package topologyD

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

// run_lldpcli_show() runs the "lldpcli show «arg»" command, capturing its output.
//
// Returns output byte slice or error.
//
// TODO(mw) triplicate code
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

// LldpcliChassisMember is the outermost layer of the nested "lldpcli show
// chassis" JSON format data structure. It is used for containing the parsed
// JSON representation returned by the command output.
//
// These data structures were automatically converted from lldpcli JSON output
// to Go using an online type converter
// https://mholt.github.io/json-to-go/
// and then manually pieced apart into substructures.
type LldpcliChassisMember struct {
	ID struct {
		Type  string             `json:"type,omitempty"`
		Value string             `json:"value,omitempty"`
	}                            `json:"id,omitempty"`
	Descr      string            `json:"descr,omitempty"`
	// this is sometimes an array, sometimes a string... declare as interface{}
	// and fix further down
	MgmtIP     interface{}       `json:"mgmt-ip,omitempty"`
	Capability json.RawMessage   `json:"capability,omitempty"`
	// FIXME(mw) Once again, Capability can be slice of struct, or just the struct itself. Since it's currently unused, I don't want to bother parsing it right now.
    //Capability struct {
	//	Type    string           `json:"type,omitempty"`
	//	Enabled bool             `json:"enabled,omitempty"`
	//}
}

// LldpcliChassisMap is a data structure for unwrapping the outermost layer of
// lldpcli JSON output, which for any chassis consists of an object keyed by the
// system hostname with the machine chassis as only element in the object. This
// is impractical so it is handled and discarded locally.
type LldpcliChassisMap map[string]LldpcliChassisMember

// LldpcliChassisInfo is another wrapper data structure used for untangling
// lldpcli's messy JSON output.
type LldpcliChassisInfo struct {
	LocalChassis struct {
		// see comment for LldpcliNeighborInfo.Lldp
		Chassis json.RawMessage  `json:"chassis,omitempty"`
	}                            `json:"local-chassis,omitempty"`
}

// LldpcliNeighborPortID is a container type for unwrapping a tuple of PortID
// type and the actual identifier, both represented as strings in "lldpcli show
// neighbors" JSON output.
type LldpcliNeighborPortID struct {
	Type  string                 `json:"type,omitempty"`
	Value string                 `json:"value,omitempty"`
}

// LldpcliNeighborPort is a substructer referring to the neighbor port in
// "lldpcli show neighbors" JSON output.
type LldpcliNeighborPort struct {
	ID    LldpcliNeighborPortID  `json:"id,omitempty"`
	Descr string                 `json:"descr,omitempty"`
	TTL   string                 `json:"ttl,omitempty"`
}

// LldpcliNeighborInterface is a substructure for unwrapping the neighbor's
// interface.
type LldpcliNeighborInterface struct {
	Via     string               `json:"via,omitempty"`
	Rid     string               `json:"rid,omitempty"`
	Age     string               `json:"age,omitempty"`
	Chassis LldpcliChassisMap    `json:"chassis,omitempty"`
	Port    LldpcliNeighborPort  `json:"port,omitempty"`
}

// LldpcliNeighborInfo is a container type for unwrapping "lldpcli show
// neighbors" JSON output.
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

// LldpcliNeighborInterfaceMap is a map type for interface name to neighbours
// found on that interface.
type LldpcliNeighborInterfaceMap map[string]*LldpcliNeighborInterface

/**** JSON Parsing and handling of format weirdnesses *********************************/

// (*LldpcliChassisMember).fix_mgmt_ip() forces the MgmtIP array of the JSON
// output into a usable format. The MgmtIP field can be either an array of IP
// addresses in case of multiple reported addresses, or a string in case there
// is only one, so it needs special treatment. It is stored after the typecast
// to []string and sorting into «chassis».
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

// (*LldpcliChassisMember).get_idtype() returns the type of Chassis ID of
// «chassis».
func (chassis *LldpcliChassisMember) get_idtype() (idtype IdentifierType) {
	idtype, ok := idtype_map[chassis.ID.Type]
	if !ok {idtype = IDTYPE_UNKNOWN}
	return
}

// lldp_parse_chassis_data() parses "lldpcli -f json show chassis" output found
// in byte slice «b».
//
// Returns parsed structure as «ret» on sucess or «err» on error.
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

// IdentifierType is an enum type for the different types of LLDP IdType as
// reported by lldpd.
type IdentifierType int
const (
	IDTYPE_UNKNOWN IdentifierType = iota
	IDTYPE_MAC
	IDTYPE_LOCAL
	IDTYPE_IFNAME
)

// A map from string values to IdentifierType enum values for internal use by
// JSON conversion.
var idtype_map = map[string]IdentifierType{
	"mac":     IDTYPE_MAC,
	"local":   IDTYPE_LOCAL,
	"ifname":  IDTYPE_IFNAME,
	"unknown": IDTYPE_UNKNOWN,
}

// (IdentifierType).String() returns the string representation of «t».
func (t IdentifierType) String() string {
	return []string{"unknown", "mac", "ifname", "local"}[t]
}

// (IdentifierType).MarshalJSON() is the implementation of the json.Marshaler
// interface for the IdentifierType enum.
//
// Returns the JSON representation of «t» as byte slice, or a value of type
// error in case of an error.
func (t IdentifierType) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

// (*IdentifierType).UnmarshalJSON() is the implementation of the
// json.Unmarshaler interface for the IdentifierType enum.
// Converts JSON string values to IdType enum values.
//
// Modifies «t» in case of success and returns an error otherwise.
func (t *IdentifierType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	v, ok := idtype_map[s]
	if !ok {
		*t = IDTYPE_UNKNOWN
		return fmt.Errorf("%q is not a valid identifier type", s)
	}
	*t = v
	return nil
}

// Neighbor{} contains the same information as LldpcliNeighborInfo but
// sensibly flattened. This type is used throughout the entire program to refer
// to LLDP neighbors, both received via topologyd API calls to remote lldpd or
// received via SNMP lookups.
type Neighbor struct {
	Identifier         string            `json:"Identifier"`      // Unique identifier used by this machine (typically MAC address)
	IdType             IdentifierType    `json:"IdentifierType"`  // Type of Identifier field (MAC, LOCAL, UNKNOWN)
	Descr              string            `json:"Description"`     // Description (uname output unless altered by config file)
	Hostname           string            `json:"Hostname"`        // Hostname (e.g. DC3500 something)
	SourceIface        string            `json:"SourceInterface"` // Interface name on which this neighbor was found by the neighbor reporting it
	SourceNeighbor     string            `json:"SourceNeighbor"`  // Primary MgmtIP address of neighbor which found this neighbor via LLDP
	MgmtIPs            MgmtIPs           `json:"MgmtIPs"`         // Management IPs of this neighbor reported by LLDP
	Origin             OriginType        `json:"Origin"`          // Whether this neighbor was obtained via topologyd's http API or SNMP
	// FIXME(mw) include neighborIface.Port (i.e. the remote port) in the data
	// structure if desirable later
}

// OriginType is an enum for the different types of lookup that can result in a Neighbor
type OriginType int
const (
	ORIGIN_LOCAL      OriginType = iota                           // host found in local lldpcli json output
	ORIGIN_TOPOLOGYD                                              // found by topologyd API lookup
	ORIGIN_SNMP                                                   // found by SNMP lookup
	ORIGIN_ICMP                                                   // node responded to broadcast ping
// TODO(mw) add JSON marshaler/unmarshaler for this enum
)

// LocalChassis is a type alias for Neighbor. The local chassis data is almost
// the same format, except that SourceIface and potentially some other fields
// are unset. This type alias exists to be able to differentiate between a local
// chassis or remote neighbor on the type system level.
type LocalChassis Neighbor

// NeighborSlice is a type alias for slice of neighbor, to be able to define
// receiver functions for the type.
type NeighborSlice []Neighbor

// NeighborLookupResult{} is a struct type for storing all data received from a
// single machine in a single container. The different data originates from
// multiple separate lookups, but is all associated with a single host.
type NeighborLookupResult struct {
	ns		          NeighborSlice                              // list of neighbors received from this host
	origin            OriginType                                 // whether this node communicated via SNMP or topologyd
	ip                string                                     // IP address this was received from
	mac               string                                     // MAC address of this host
	stp               PortToStateMap    `json:"STPPortState"`    // STP port state as reported by this neighbor
	snmp_locportdata  PortDataMap                                // Network port table of this host received via SNMP
}

// lldpcli_neighbor_interface_map_to_neighbor() is the function for flattening
// «ifmap» to type Neighbor. There should only ever be one element in this map,
// and not all data is actually used. «host» is stored inside the Neighbor{} as
// the origin of the data.
//
// Returns «res» on success or an empty struct on error.
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
			Origin: 3232,
		}
		res.ValidateHostname()
		return
	}
	return
}

// parse_lldpcli_neighbors_output() parses "lldpcli -f json show neighbors"
// output «b», setting «host» as the source for the data.
//
// Returns NeighborSlice on success, or error on error.
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

// (*Neighbor).ValidateHostname() checks whether the hostname for neighbors
// received via LLDP matches the global hostname prefix configured in ARGV for
// the network to make sure the network does not contain any unexpected
// computers. Prints a log message in case it finds such a hostname.
func (n *Neighbor) ValidateHostname() {
	if !(ARGV.host_prefix <= (*n).Hostname) {
        log.Printf("Found machine '%s' which is seemingly not a %s: %+v", n.Identifier,
            ARGV.host_prefix, n)
	}
}

// (Neighbor).IsEmpty() checks whether or not this Neighbor has been
// initialized, or whether it is an empty/bogus Neighbor.
//
// Returns true if «n» contains any data.
func (n Neighbor) IsEmpty() bool {
	// explicitly not checking for SourceIface, sometimes Microsens SNMP gets
	// such responses for ports where nothing is connected
	return n.Descr == "" &&
		n.Hostname == "" &&
		n.IdType == IDTYPE_UNKNOWN &&
		n.Identifier == "" &&
		len(n.MgmtIPs) == 0
}

/**** NeighborSlice receiver functions ************************************************/

// (*NeighborSlice).get_hostnames() gets the hostnames of all neighbors from
// «ns».
//
// Returns a map from MgmtIP to the Neighbor's hostname reported via LLDP.
func (ns *NeighborSlice) get_hostnames() (res map[string]string) {
	res = make(map[string]string, len(*ns))
	for _, n := range *ns {
		mgmt_ip, err := n.MgmtIPs.get_suitable_mgmt_ip()
		if err != nil {
			log.Printf("Error getting MgmtIP from host %+v: %s", n, err)
		}
		res[mgmt_ip] = n.Hostname
	}
	return
}

// (*NeighborSlice).get_mgmt_ips() gets MgmtIPs, one MgmtIP per host, from «ns».
// Logs errors internally.
//
// Returns a slice «res» of one MgmtIP per host for a slice of Neighbor structs,
// or empty slice on error.
func (ns *NeighborSlice) get_mgmt_ips() (res []string) {
	res = make([]string, len(*ns))
	for i, n := range *ns {
		mgmt_ip, err := n.MgmtIPs.get_suitable_mgmt_ip()
		if err != nil {
			log.Printf("Error getting MgmtIP from host %+v: %s", n, err)
		}
		res[i] = mgmt_ip
	}
	return
}

// (*NeighborSlice).find_neighbor_by_ip() finds the Neighbor{} associated with
// the MgmtIP «ip» from «ns».
//
// Returns the neighbor that has this IP address, or an empty Neighbor if not
// found. Also returns whether the IP address was found in «ns» as a boolean.
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

// get_local_neighbors() runs "lldpcli show neighbors" on the local machine and
// parses its output.
//
// Returns the parsed output «ns», or «err» on error.
func get_local_neighbors() (ns NeighborSlice, err error) {
	bytes, err := run_lldpcli_show("neighbors")
	if err != nil {return}
	// LOCAL in all caps is used here to signify that this information didn't
	// come from a remote topologyd on the network but from locally run lldpcli
	// TODO(mw) replace by local identifier from lldp chassis?
	ns, err = parse_lldpcli_neighbors_output("LOCAL", bytes)
	return
}

// MgmtIPs is a type alias for defining receiver functions for a slice of MgmtIPs.
type MgmtIPs []string

// (*MgmtIPs).Contains() performs a linear search for «ip» in «M».
//
// Returns true if found, false otherwise.
func (M *MgmtIPs) Contains(ip string) bool {
	for _, v := range *M {
		if ip == v {return true}
	}
	return false
}

// (MgmtIPs).get_suitable_mgmt_ip() is used to pick a MgmtIP from «M», which are
// assumed to be MgmtIPs assigned to the same host (LLDP supports announcing
// multiple MgmtIPs per machine). It picks the best looking one according to
// policy defined in ARGV. This MgmtIP is then considered the "primary MgmtIP"
// for that machine, and used as its unique identifier.
//
// Returns a MgmtIP or an error.
func (M MgmtIPs) get_suitable_mgmt_ip() (string, error) {
	if len(M) < 1 {
		return "", fmt.Errorf("no IP address found for Neighbor (is it defined?)")
	}

	// For machines that have Link Local/IPv6 management addresses available,
	// prefer those over any other type of address returned by lldpd, depending
	// on what's configured in ARGV.
	if ARGV.prefer_link_local || ARGV.prefer_ipv6 {
		for _, v := range M {
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
	return M[0], nil
}

// get_local_chassis_mgmt_ips() runs and parses the output of "lldpcli show
// chassis" to obtain the local machine's MgmtIPs.
//
// Returns the management IPs «mgmtIPs» or «err» on error.
func get_local_chassis_mgmt_ips() (mgmtIPs MgmtIPs, err error) {
	bytes, err := run_lldpcli_show("chassis")
	if err != nil {return}
	chassis, err := lldp_parse_chassis_data(bytes)
	if err != nil {return}
	mgmtIPs = chassis.MgmtIPs
	return
}

// (NeighborSlice).Compare() compares a set of «neighbors» to another set of
// neighbors «peers» and determines three sets of neighbors: which ones are
// expected and present (quiescent), which ones are present but unexpected
// (excess) and which ones are missing. Used for monitoring.
// Logs errors internally.
//
// Returns «r», suitable for marshaling to JSON.
func (neighbors NeighborSlice) Compare(peers NeighborSlice) (r TopologyStatusResponse) {
	// TODO(mw) this function isn't optimized for efficiency. Seems like O(n^2)
	// TODO(mw) refactor: use golang-set/mapset module (not part of the standard lib)
	seen := make(map[string]bool, len(neighbors))

	// Step 1: set all IPs from neighbors to false in the map
	for _, n := range neighbors {
		ip, err := n.MgmtIPs.get_suitable_mgmt_ip()
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
		// FIXME(mw) rather than get_suitable_management_ips here the check should be MgmtIPs.Contains()
		ip, err := n.MgmtIPs.get_suitable_mgmt_ip()
		if err != nil {
			log.Printf("Error getting MgmtIP from Neighbor %+v: %s", n, err)
			continue
		}
		if _, exists := seen[ip]; !exists {
			r.Excess = append(r.Excess, n)
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
				// FIXME(mw) see above
				n_ip, err := n.MgmtIPs.get_suitable_mgmt_ip()
				if err != nil {continue} // error already logged in step 1 or 2
				if ip == n_ip {
					r.Missing = append(r.Missing, n)
					break
				}
			}
		}
	}

	// Step 4: add IPs which are found but whose characteristics do
	// not match to mismatching, with information about the mismatch.
	for _, p := range to_check {
		for _, n := range neighbors {
			// FIXME(mw) see above
			n_ip, err := n.MgmtIPs.get_suitable_mgmt_ip()
			if err != nil {continue} // error already logged in step 1
			p_ip, err := p.MgmtIPs.get_suitable_mgmt_ip()
			if err != nil {continue} // error already logged in step 2

			if n_ip != p_ip {continue} // not the peer we're looking for

			if match, reason := compare_neighbors(&n, &p); match {
				r.Quiescent = append(r.Quiescent, p)
			} else {
				r.Mismatching = append(r.Mismatching, NeighborWithError{
					Neighbor: p,
					Reason:   reason,
				})
			}
		}
	}

	return
}

// check_neigh() is an internal function of check_ips(). It compares a string
// value «nvalue» from a neighbor defined in the quiescent topology to a
// real neighbor's value «pvalue» of the same «key» (e.g. "SourceIface" or
// "Hostname"), and if they mismatching generates a Reason{} with a mismatch
// message that also includes the host's «ip».
//
// Returns bool whether they match and a Reason{} in case they do.
func check_neigh(ip string, key string, nvalue string, pvalue string) (bool, Reason) {
	if nvalue == pvalue { return true, Reason{} }

	msg := fmt.Sprintf("%s mismatch for IP %s. Expected '%s', got '%s'",
		key, ip, nvalue, pvalue)

	return false, Reason{
		Message:   msg,
		Key:       key,
		Expected:  nvalue,
		Value:     pvalue,
	}
}

// check_ips() is an internal function of compare_neighbors(). Compares a node's
// IPs «nips» with a peer's IPs «pips». Includes the host's «ip» in the mismatch
// Reason string.
//
// Returns true if they match and false and a Reason{} if they don't.
func check_ips(ip string, nips []string, pips []string) (bool, Reason) {
	sort.Strings(nips)
	sort.Strings(pips)

	if len(nips) != len(pips) {goto not_equal}

	for i := range nips {
		if nips[i] != pips[i] {
			goto not_equal
		}
	}
	return true, Reason{}

not_equal:
	return false, Reason{
		Message: fmt.Sprintf(
			"MgmtIP mismatch for IP %s. Expected '%v', got '%v'",
			ip, nips, pips,
		),
		Key: "MgmtIPs",
		Expected: fmt.Sprintf("%+v", nips),
		Value: fmt.Sprintf("%+v", pips),
	}
}

// compare_neighbors() is an internal function of (NeighborSlice).Compare().
// Compares two neighbors «n» and «p», where «n» is defined in the quiescent
// topology and «p» is seen on the live network via LLDP. Used for monitoring.
//
// Returns true if they match, or false and a slice of Reason{}s if not.
func compare_neighbors(n *Neighbor, p *Neighbor) (bool, []Reason) {
	var ok        bool
	var r         Reason
	var reasons []Reason

	ip, err := n.MgmtIPs.get_suitable_mgmt_ip()
	if err != nil {
		msg := fmt.Sprintf("Internal error: failed to get MgmtIP from node %v",
			n)
		log.Println(msg)
		return false, []Reason{ Reason{Message: msg} }
	}

	ok,r = check_neigh(ip, "Description", n.Descr,      p.Descr)
	if !ok {reasons = append(reasons, r)}

	ok,r = check_neigh(ip, "Identifier",  n.Identifier, p.Identifier)
	if !ok {reasons = append(reasons, r)}

	ok,r = check_neigh(ip, "IdType",      n.IdType.String(), p.IdType.String())
	if !ok {reasons = append(reasons, r)}

	ok,r = check_neigh(ip, "Hostname",    n.Hostname,   p.Hostname)
	if !ok {reasons = append(reasons, r)}

	ok,r = check_neigh(ip, "SourceIface", n.SourceIface, p.SourceIface)
	if !ok {reasons = append(reasons, r)}

	ok,r = check_ips(ip, n.MgmtIPs, p.MgmtIPs)
	if !ok {reasons = append(reasons, r)}

	return len(reasons) == 0, reasons
}
