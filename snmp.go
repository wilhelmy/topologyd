package main

import (
	//"fmt"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

func snmp_init() {
	log_snmp("snmp_init")

	// verbose logging? always on for now
	//gosnmp.Default.Logger  = gosnmp.NewLogger(log.Default())
	gosnmp.Default.Version = gosnmp.Version2c;
	gosnmp.Default.ExponentialTimeout = false;
	gosnmp.Default.Timeout = time.Duration(2) * time.Second
	gosnmp.Default.Retries = 2;
	// TODO set gosnmp.Default.Timeout, Retries, Community, Port from ARGV
}

/**** Helper functions ****************************************************************/
// snmp_connect creates a handler and connects.
func snmp_connect(host string) (snmp gosnmp.Handler, err error) {
	snmp = gosnmp.NewHandler()
	snmp.SetTarget(fix_linklocal(host))
	snmp.SetLogger(gosnmp.Default.Logger)
	snmp.SetTimeout(20*time.Second) //FIXME
	err = snmp.Connect()
	return
}

// gosnmp 1.37.0 has a bug with requesting OIDs with trailing dots. This works
// around it by removing them.
// https://github.com/gosnmp/gosnmp/issues/480
func snmp_bulkwalk(snmp gosnmp.Handler, oid string, walkFn gosnmp.WalkFunc) error {
	return snmp.BulkWalk(strings.TrimSuffix(oid, "."), walkFn)
}

// snmp_print prints a dataUnit in a somewhat human readable format
func snmp_print(dataUnit gosnmp.SnmpPDU) {
	if !ARGV.snmp_verbose {return}
	if dataUnit.Type == gosnmp.OctetString {
		bytes := dataUnit.Value.([]byte)
		log.Printf("%s (%s) = %s", dataUnit.Name, dataUnit.Type.String(), string(bytes))
	} else if dataUnit.Type == gosnmp.Integer {
		log.Printf("%s (%s) = %d", dataUnit.Name, dataUnit.Type.String(), dataUnit.Value.(int))
	} else {
		log.Println(dataUnit)
	}
}

// snmp_cut returns whether suboid is an instance of oid, and if so, the suboid
// string with the oid prefix removed
func snmp_cut(oid string, suboid string) (bool, string) {
	// in case oid does not have a trailing dot, add it to even the playfield
	if !strings.HasSuffix(oid, ".")    {oid    += "."}

	if strings.HasPrefix(suboid, oid) {
		return true, suboid[len(oid):]
	}
	return false, ""
}

// snmp_tostring casts a PDU value that's expected to be a string as a string,
// and returns an error if the type cast fails.
func snmp_tostring(v gosnmp.SnmpPDU) (r string, err error) {
	rv, ok := v.Value.([]byte)
	if !ok {
		return "", fmt.Errorf(
			"Invalid SNMP response for %s, string expected, got (%s) %s",
			v.Name, v.Type.String(), v.Value)
	}
	r = string(rv)
	return
}

// snmp_toint casts a PDU value that's expected to be an int as an int,
// and returns an error if the type cast fails.
func snmp_toint(v gosnmp.SnmpPDU) (r int, err error) {
	r, ok := v.Value.(int)
	if !ok {
		return -1, fmt.Errorf(
			"Invalid SNMP response for %s, int expected, got (%s) %s",
			v.Name, v.Type.String(), v.Value)
	}
	return
}

// snmp_err_invalid_oid_index generates errors when parsing indexes of suboids
// such as when three digits like ...0.101.0 are expected but only two ...0.101 are found
func snmp_oid_err_invalid_index(oid string, expected int, received int) error {
	return fmt.Errorf(
		"SNMP: OID (%s) contained unexpected sequence of index integers (expected %d, got %d)",
		oid, expected, received)
}


// snmp_oid_cutval cuts a value out of the middle of an OID/SubOID and returns
// it, such that calling it with ".0.101.1", 3 and 1 returns 101. If the
// arguments don't match the expectations it returns an error.
func snmp_oid_cutval(oid string, expected int, num int) (int, error) {
	s := strings.Split(strings.Trim(oid, "."), ".")
	received := len(s)
	if expected < num {expected = num}
	if received != expected {
		return -1, snmp_oid_err_invalid_index(oid, expected, received)
	}
	iv, err := strconv.Atoi(s[num])
	if err != nil {return -1, err}

	return iv, nil
}

/**** Constants ***********************************************************************/
// SNMP LLDP OIDs. Poor man's MIB :)
// S_ is short for SNMP, the names of the identifiers and the OID mapping are
// sourced from LLDP-MIB.
const (
	S_LLDP                 = ".1.0.8802.";
	// Local information: LLDP local chassis
	S_LOC                  = ".1.0.8802.1.1.2.1.3.";
	/*S_LOCCHASSISIDSUBTYPE
	S_LOCCHASSISID
	S_LOCSYSNAME
	S_LOCSYSDESC
	S_LOCSYSCAPSUPPORTED
	S_LOCSYSCAPENABLED*/
	S_LOCPORT             = ".1.0.8802.1.1.2.1.3.7.";
	S_LOCPORTNUM          = ".1.0.8802.1.1.2.1.3.7.1.1.";
	S_LOCPORTIDSUBTYPE    = ".1.0.8802.1.1.2.1.3.7.1.2.";
	S_LOCPORTID           = ".1.0.8802.1.1.2.1.3.7.1.3.";
	S_LOCPORTDESC         = ".1.0.8802.1.1.2.1.3.7.1.4.";
	/*S_LOCMANADDRSUBTYPE
	S_LOCMANADDR
	S_LOCMANADDRLEN
	S_LOCMANADDRIFSUBTYPE
	S_LOCMANADDRIFID
	S_LOCMANADDROID*/

	// Remote information: LLDP neighbor chassis
	S_REM                  = ".1.0.8802.1.1.2.1.4.";
	S_REMCHASSISIDSUBTYPE  = ".1.0.8802.1.1.2.1.4.1.1.4.";
	S_REMCHASSISID         = ".1.0.8802.1.1.2.1.4.1.1.5.";
	S_REMPORTIDSUBTYPE     = ".1.0.8802.1.1.2.1.4.1.1.6.";
	S_REMPORTID            = ".1.0.8802.1.1.2.1.4.1.1.7.";
	S_REMSYSNAME           = ".1.0.8802.1.1.2.1.4.1.1.9.";
	S_REMSYSDESC           = ".1.0.8802.1.1.2.1.4.1.1.10.";
	S_REMSYSCAPSUPPORTED   = ".1.0.8802.1.1.2.1.4.1.1.11.";
	S_REMSYSCAPENABLED     = ".1.0.8802.1.1.2.1.4.1.1.12.";
	S_REMSYSMANADDRSUBTYPE = ".1.0.8802.1.1.2.1.4.2.1.1.";
	S_REMSYSMANADDR        = ".1.0.8802.1.1.2.1.4.2.1.2.";
)

/* wishful thinking that we can query only these and gain performance...
func _snmp_oids_we_care_about() []string {
	return []string{
		S_REMCHASSISIDSUBTYPE, S_REMCHASSISID, S_REMPORTIDSUBTYPE, S_REMPORTID,
		S_REMSYSNAME, S_REMSYSDESC, S_REMSYSMANADDRSUBTYPE, S_REMSYSMANADDR,
	}
}*/

// TODO SNMP interface OID's --- do we care about these later, perhaps?
/* const (

        "ifnumber": ".1.3.6.1.2.1.2.1.",
        "ifdesc": ".1.3.6.1.2.1.2.2.1.2.",
        "ifmtu": "1.3.6.1.2.1.2.2.1.4",
        "ifspeed": ".1.3.6.1.2.1.2.2.1.5.",
        "ifmac": ".1.3.6.1.2.1.2.2.1.6.",
        "ifname": ".1.3.6.1.2.1.31.1.1.1.1.",
        "ifalias": ".1.3.6.1.2.1.31.1.1.1.18."
        )*/

/*
func snmp_lookup_chassis(host string) {
}
*/

// SNMP-LLDP Port ID type, as defined in LLDP-MIB
type S_LldpPortIdSubtype int

// PortIDSubtype values enum
const (
	S_InterfaceAlias S_LldpPortIdSubtype = 1
	S_PortComponent = iota
	S_MacAddress
	S_NetworkAddress
	S_InterfaceName
	S_AgentCircuitId
	S_Local
)

// SNMP OIDs for obtaining the STP port state - from BRIDGE-MIB
const (
	S_STPPORTSTATE = ".1.3.6.1.2.1.17.2.15.1.3";
)

type NodeSnmpData struct {
	ports        PortData
	portnum      int
}

// A data structure for storing the Port Identifier as obtained by
// snmp_collect_locport_data
type PortData struct {
	PortNum       int
	PortIDSubtype S_LldpPortIdSubtype
	PortID        string
	PortDesc      string
}

// A data structure for storing a map from switch internal port ID (integer) to
// that port's data (human readable label etc.)
type PortDataMap map[int]PortData

// snmp_collect_locport_data is the callback routine for collecting the data on
// network ports in a BulkWalk request.
func snmp_collect_locport_data(dataUnit gosnmp.SnmpPDU, ports PortDataMap) (err error) {
	var iidx int
	if is,idx := snmp_cut(S_LOCPORTNUM, dataUnit.Name); is {
		var iidx2 int
		// idx but converted to integer
		iidx, err = strconv.Atoi(idx)
		if err != nil {return}

		// this should be identical to idx, otherwise return an error
		iidx2, err = snmp_toint(dataUnit)
		if err != nil {return}

		if iidx != iidx2 {
			return fmt.Errorf("ERROR: This switch does terrible things with network port "+
				"indexes. Got %s but it should be %d",
				idx, iidx)
		}
		port, exists := ports[iidx]
		if !exists { port = PortData{} }
		port.PortNum = iidx
		ports[iidx] = port

	} else if is,idx := snmp_cut(S_LOCPORTIDSUBTYPE, dataUnit.Name); is {
		var ival int
		iidx, err = strconv.Atoi(idx)
		port, exists := ports[iidx]
		if !exists { port = PortData{} }
		ival, err  = snmp_toint(dataUnit)
		if err != nil {return}
		port.PortIDSubtype = S_LldpPortIdSubtype(ival)

		if ival <= 0 || ival > int(S_Local) {
			return fmt.Errorf(
				"Received invalid value for PortID Subtype (%d is out of range)", ival)
		}
		ports[iidx] = port

	} else if is,idx := snmp_cut(S_LOCPORTID, dataUnit.Name); is {
		var sval string
		iidx, err = strconv.Atoi(idx)
		if err != nil {return}
		port, exists := ports[iidx]
		if !exists { port = PortData{} }
		sval, err = snmp_tostring(dataUnit)
		if err != nil {return}
		port.PortID = sval
		ports[iidx] = port

	} else if is,idx := snmp_cut(S_LOCPORTDESC, dataUnit.Name); is {
		var sval string
		iidx, err = strconv.Atoi(idx)
		if err != nil {return}
		port, exists := ports[iidx]
		if !exists { port = PortData{} }
		sval, err = snmp_tostring(dataUnit)
		if err != nil {return}
		port.PortDesc = sval
		ports[iidx] = port
	}

	return
}

// wow, lots of boilerplate and no nice way to express it!
func snmp_collect_neighbors(dataUnit gosnmp.SnmpPDU, neighbors map[int]Neighbor, ports PortDataMap) (err error) {
	snmp_print(dataUnit)
	n := Neighbor{ Origin: ORIGIN_SNMP }

	var is bool
	var idx string = "YOLO"
	var iidx int

	//snmp_print(dataUnit)

	if is,idx = snmp_cut(S_REMCHASSISIDSUBTYPE, dataUnit.Name); is {
		/* possible values for Chassis ID Subtype (see LLDP-MIB) */
		/* 'chassisComponent(1)'
		 * 'interfaceAlias(2)'
		 * 'portComponent(3)'
		 * 'macAddress(4)'
		 * 'networkAddress(5)'
		 * 'interfaceName(6)'
		 * 'local(7)'
 		 */
		iidx, err = snmp_oid_cutval(idx, 3, 1)
		if err != nil {return}
		n, _ = neighbors[iidx]

		idtype, err := snmp_toint(dataUnit)
		if err != nil {return err}

		if idtype == 4 {
			n.IdType = MAC_ID
		} else if idtype == 6 {
			n.IdType = IFNAME_ID
		} else if idtype == 7 {
			n.IdType = LOCAL_ID
		} else { /* anything else is not supported right now */
			n.IdType = UNKNOWN_ID
		}
		neighbors[iidx] = n
	} else if is,idx = snmp_cut(S_REMCHASSISID, dataUnit.Name); is {
		iidx, err = snmp_oid_cutval(idx, 3, 1)
		if err != nil {return}
		n, _ = neighbors[iidx]
		if n.Identifier, err = snmp_tostring(dataUnit); err != nil {return}
		neighbors[iidx] = n
	} else if is,idx = snmp_cut(S_REMPORTIDSUBTYPE, dataUnit.Name); is {
		/* possible values for Port ID Subtype (see LLDP-MIB) */
		/* 'interfaceAlias(1)'
		 * 'portComponent(2)'
		 * 'macAddress(3)'
		 * 'networkAddress(4)'
		 * 'interfaceName(5)'
		 * 'agentCircuitId(6)'
		 * 'local(7)'
		 */
		// Currently only 5 is supported and this is used implicitly
		// This corresponds to an interface name (e.g. br0, eth0) on Linux, but
		// other OSes (especially some weird managed switch OS) might have other
		// conventions. However it's only ever used as a string for printing, so
		// just print a warning if it's something else and move on.
		iidx, err = snmp_oid_cutval(idx, 3, 1)
		if err != nil {return}
		idtype, err := snmp_toint(dataUnit)
		if err != nil {return err}

		if idtype != 5 {
			log.Println("Eeep! SNMP Neighbor reported strange Port ID type:", idtype)
		}
		// FIXME this should be assigned in here?
	} else if is,idx = snmp_cut(S_REMPORTID, dataUnit.Name); is {
		iidx, err = snmp_oid_cutval(idx, 3, 1)
		if err != nil {return}
		n, _ = neighbors[iidx]
		if n.SourceIface, err = snmp_tostring(dataUnit); err != nil {return}
		neighbors[iidx] = n
	} else if is,idx = snmp_cut(S_REMSYSNAME, dataUnit.Name); is {
		iidx, err = snmp_oid_cutval(idx, 3, 1)
		if err != nil {return}
		n, _ = neighbors[iidx]
		if n.Hostname, err = snmp_tostring(dataUnit); err != nil {return}
		neighbors[iidx] = n
	} else if is,idx = snmp_cut(S_REMSYSDESC, dataUnit.Name); is {
		iidx, err = snmp_oid_cutval(idx, 3, 1)
		if err != nil {return}
		n, _ = neighbors[iidx]
		if n.Descr, err = snmp_tostring(dataUnit); err != nil {return}
		neighbors[iidx] = n

	/* S_REMSYSCAPSUPPORTED S_REMSYSCAPENABLED would go here if we cared about
	   LLDP device capability flags. They're not currently used anywhere else. */
	/* 'other(0)'
	 * 'repeater(1)'
	 * 'bridge(2)'
	 * 'wlanAccessPoint(3)'
	 * 'router(4)'
	 * 'telephone(5)'
	 * 'docsisCableDevice(6)'
	 * 'stationOnly(7)'
	 */

	} else if is,idx = snmp_cut(S_REMSYSMANADDRSUBTYPE, dataUnit.Name); is {
		/* SNMP is showing its age here. We support 1 and 2 here, everything
		   else can rot in hell. */
		/* 'ipV4(1)'
           'ipV6(2)' */
		// the management address related OIDs return only 2 numbers instead of 3.
		idtype, err := snmp_toint(dataUnit)
		if err != nil {return err}
		if idtype != 1 && idtype != 2 {
			log.Println("Eeep! SNMP Neighbor reported strange Management IP address family type:", idtype)
		}
		// FIXME should this be assgined back into the neighbor?

		// As this isn't stored anywhere, there isn't much point retrieving it.
		// We're parsing the management address as both IPv4 and IPv6 below and
		// if that doesn't work out then we won't be friends.
	} else if is,idx = snmp_cut(S_REMSYSMANADDR, dataUnit.Name); is {
		// Seems at least Mikrotik's SNMP implementation  only reports one IP
		// address here? Kind of nasty when there's multiple addresses assigned
		// and we're interested in one particular address family (IPv6 in our
		// case) but such is life.

		// FIXME this feature seems to be broken in microsens' firmware
		iidx, err = snmp_oid_cutval(idx, 2, 1)
		if err != nil {return}
		n, _ = neighbors[iidx]

		var ip string
		if ip, err = snmp_tostring(dataUnit); err != nil {return}

		n.MgmtIPs = append(n.MgmtIPs, ip)
		neighbors[iidx] = n
	}

	//if is {log.Printf("'%+v'(%T): %+v", idx, idx, neighbors[iidx])}

	// If this neighbor is found in the port information assign its SourceIface
    if neigh, found := neighbors[iidx]; false && is && found {
		// FIXME is it always the last value, or only on microsens??!? check MIB and other switch impl
		port, found := ports[iidx]
		if !found {
			return fmt.Errorf("Can't find neighbor port %d although it should be there", iidx)
			return nil//FIXME
		}
		neigh.SourceIface = port.PortDesc
		neighbors[iidx] = neigh
	}

	return nil
}

func snmp_lookup_neighbors(host string) (res NeighborLookupResult, err error) {
	log_snmp("=> Entering SNMP")
	res, err = snmp_lookup_neighbors_(host)
	log_snmp("<= Leaving SNMP")
	return
}

/*
func snmp_get_source_iface(host string, ports PortDataMap) error {
	for k, v := range ports {
		//if v.PortNum ==
		return err
        }}}}}
	}
}
*/

func log_snmp(format string, arg... interface{}) {
    if ARGV.snmp_verbose {
        log.Printf(format, arg...)
    }
}

func snmp_get_node_locport_data(host string) (ret PortDataMap) {
	log_snmp("=> Entering SNMP/LocPort Disco")
    ret = snmp_get_node_locport_data_(host)
	log_snmp("<= Leaving SNMP/LocPort Disco")
	return
}

func snmp_get_node_locport_data_(host string) (ret PortDataMap) {
	var err error
	snmp, err := snmp_connect(host)
	if err != nil {return}
	ret = make(PortDataMap)
	// First, walk local port data to obtain the names and indices of the
	// network ports on the switch
	if err = snmp_bulkwalk(snmp, S_LOCPORT, func(pdu gosnmp.SnmpPDU) error {
		// closure for passing out data
		snmp_print(pdu)
		return snmp_collect_locport_data(pdu, ret)
	}); err != nil {
		log.Println("SNMP lookup aborted due to error:", err)
		return nil
	}

	return
}

// Discover LLDP neighbors queried from a neighbor node via SNMP
func snmp_lookup_neighbors_(host string) (res NeighborLookupResult, err error) {
	// XXX it would be nice here go use GetBulk rather than BulkWalk to only
	// fetch _snmp_oids_we_care_about() to save some traffic, on the other
	// hand there is a minimum amount of fields in 1.0.8802 we don't care about
	// and the entire lookup finishes in 2 SNMP requests on the test setup.
	snmp, err := snmp_connect(host)
	if err != nil {return}
	var ports PortDataMap

	// Maps SNMP indexes of LLDP-MIB::lldpRemEntry to corresponding Neighbor
	// struct while the individual fields are being gathered
	neighbors := make(map[int]Neighbor)

	if err = snmp_bulkwalk(snmp, S_REM, func(pdu gosnmp.SnmpPDU) error {
		// closure that captures the neighbors map to pass values out
		return snmp_collect_neighbors(pdu, neighbors, ports)
	}); err != nil {
		log.Println("SNMP lookup aborted due to error:", err)
		return
	}

	// TODO MikroTik RouterOS does not support returning multiple MgmtIP
	// addresses and (R)STP port state via SNMP. This needs to be added later in
	// case the new switch supports it.  Seems SNMP is not quite a rigorous
	// standard despite a bazillion pages of ASN.1 I had to BulkWalk with my
	// poor eyes and brain.

	// Insert the SNMP source IP into the return value entries, while tossing
	// out the map keys (these are not required and only used for grouping the
	// individual values for a host together into a dataset within the snmp PDU
	// handler function)
	var ret NeighborSlice
	for _,v := range neighbors {
		v.Origin         = ORIGIN_SNMP
		v.SourceNeighbor = host
		//v.SourceIface    = //passed in through
		ret = append(ret, v)
	}

	ports = snmp_get_node_locport_data(host)
	res = NeighborLookupResult{
		ns:               ret,
		origin:           ORIGIN_SNMP,
		ip:               host,
		snmp_locportdata: ports,
	}

	log.Printf("XXX debug %+v", res) //XXX debug
	return
}

func snmp_collect_stp_data(pdu gosnmp.SnmpPDU, stp_states map[string]int) (err error) {
	if is,idx := snmp_cut(S_STPPORTSTATE, pdu.Name); is {
		if stp_states[idx], err = snmp_toint(pdu); err != nil {return}
		//if n.SourceIface, err = snmp_toint(pdu); err != nil {return}
		snmp_print(pdu)
	} else {
		log.Println("BUG this isn't supposed to be here", pdu)
	}

	return
}

// Gathers the STP port states for all ports
func (nr *NeighborLookupResult) snmp_get_node_stp_port_state() (ret PortToStateMap) {
	snmp, err := snmp_connect(nr.ip)
	if err != nil {
		log.Printf("snmp connection failed: %s: %s", nr.ip, err)
		return nil
	}

	stp_states := make(map[string]int)

	if err = snmp_bulkwalk(snmp, S_STPPORTSTATE, func(pdu gosnmp.SnmpPDU) error {
		// closure that captures the neighbors map to pass values out
		return snmp_collect_stp_data(pdu, stp_states)
	}); err != nil {
		log.Println("SNMP lookup aborted due to error:", err)
		return
	}

	// See http://oidref.com/1.3.6.1.2.1.17.2.15.1.3
	mapping := map[int]PortState {
		// XXX is this mapping correct? mstpd only knows Discarding, Learning,
		// Forwarding and Unknown, seems some other SNMP devices might know more
		1: Discarding,       // disabled(1),
		2: Discarding,       // blocking(2),
		3: Learning,         // listening(3),
		4: Learning,         // learning(4),
		5: Forwarding,       // forwarding(5),
		6: Unknown,          // broken(6)
	}

	ret = make(PortToStateMap)
	for k,v := range stp_states {
		mapv, ok := mapping[v]
		if !ok {
			log.Println("STP: remote SNMP server returned invalid value")
			mapv = Unknown
		}
		ret[k] = mapv
	}

	//FIXME nr.snmp_locportdata = ret

	return
}
