package main

import (
	"bytes"
	"fmt"
	"log"
	"io/ioutil"
	"os"
	"os/exec"
	"encoding/json"
)

/**** Debug section *******************************************************************/
const dbg_json_verbose = false
const dbg_read_json_from_file = false

/**** lldpcli command interface *******************************************************/
func run_lldpcli_show(arg string) ([]byte, error) {
	var res []byte
	var err error

	if dbg_read_json_from_file { // i.e. for development purposes on x86 host
		fd, _ := os.Open(fmt.Sprintf("./examples/lldpcli-show-%s.json", arg))
		defer fd.Close()
		return ioutil.ReadAll(fd)

	} else {
		cmd := exec.Command("lldpcli", "-f", "json", "show", arg)

		var out bytes.Buffer
		cmd.Stdout = &out
		err = cmd.Run()
		res = out.Bytes()
	}

    return res, err
}

/**** JSON Data structures ************************************************************/
// These were automatically converted from lldpcli JSON output to Go using
// https://mholt.github.io/json-to-go/ and then manually pieced apart
// into substructures.

type ChassisMember struct {
	ID struct {
		Type  string `json:"type,omitempty"`
		Value string `json:"value,omitempty"`
	} `json:"id,omitempty"`
	Descr      string   `json:"descr,omitempty"`
	// this is sometimes an array, sometimes a string... declare as interface{}
	// and fix further down
	MgmtIP     interface{} `json:"mgmt-ip,omitempty"`
	Capability []struct {
		Type    string `json:"type,omitempty"`
		Enabled bool   `json:"enabled,omitempty"`
	} `json:"capability,omitempty"`
}

type ChassisMap map[string]ChassisMember

type ChassisInfo struct {
	LocalChassis struct {
		Chassis ChassisMap `json:"chassis,omitempty"`
	} `json:"local-chassis,omitempty"`
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
	Chassis ChassisMap      `json:"chassis,omitempty"`
	Port    NeighborPort    `json:"port,omitempty"`
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
	} `json:"lldp,omitempty"`
}

type LldpcliNeighborInterfaceMap map[string]*NeighborInterface

// Contains the same information as NeighborInfo but sensibly flattened
type NeighborSource struct {
	Name  string
	Iface NeighborInterface
}

/**** JSON Parsing and handling of format weirdnesses *********************************/
// Because the MgmtIP field can be either an array of IP addresses in case of
// multiple reported addresses, or a string in case there is only one, it needs
// special treatment. Here it gets turned into a []string.
func fix_mgmt_ip(chassis *ChassisMember) {
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
}

func get_mgmt_ip(chassis *ChassisMember) string {
	// Since this function runs after fix_mgmt_ip, the MgmtIP member should always
	// be of type []string now.
	ips, ok := (*chassis).MgmtIP.([]string)
	if !ok {
		log.Printf("MgmtIP[]: Expected []string, got %T (%s)", (*chassis).MgmtIP, (*chassis).MgmtIP)
		return ""
	} else if len(ips) < 1 {
		log.Printf("MgmtIP[]: No IP address found for chassis %+v (all empty?)", *chassis)
		return ""
	}

	return ips[0]
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

	for k, v := range c.LocalChassis.Chassis {
		fix_mgmt_ip(&v)
		c.LocalChassis.Chassis[k] = v
	}

	dbg_json(c)
	return &c, nil
}

// parses "lldpcli -f json show neighbors" output
func lldp_parse_neighbor_data(b []byte) ([]NeighborSource, error) {
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
	ifaces := make([]NeighborSource, len(inputs))

	/* loop over array of interface objects which have 1 element each such as
	   [{"eth0": <NeighborInterface>}, {"eth1": <NeighborInterface>}]
	   this is bad enough in JSON, but in Go each of these objects is
	   Unmarshaled into a map of length 1 */
	for i, ifmap := range inputs {
		if len(ifmap) > 1 {
			// XXX In this case, only the last one survives and the rest gets
			// clobbered. Should this ever happen, investigate why.
			log.Printf("Too many interfaces in JSON object - possible bug, is this really lldpcli output?")
		}

		/* k = interface name, v = struct NeighborInterface */
		for k, v := range ifmap {
			/* All MgmtIPs of type interface{} need to be coerced to []string */
			for kk, vv := range v.Chassis {
				fix_mgmt_ip(&vv)
				v.Chassis[kk] = vv
			}

			// append to return value array
			ifaces[i] = NeighborSource{k, *v}
		}
	}

	return ifaces, nil
}

func get_neighbor_mgmt_ips(src *[]NeighborSource) *[]string {
	res := make([]string, len(*src))

	for i, v := range *src {
		chassis, err := get_chassis(v.Iface.Chassis)
		if err != nil {
			log.Printf("Error: %s", err)
			continue
		}
		res[i] = get_mgmt_ip(&chassis)
	}

	return &res
}
