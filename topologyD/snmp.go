package topologyD

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// snmp_init() is called by Main() to initialize the SNMP functionality.
func snmp_init() {
	log_snmp("snmp_init")

	gosnmp.Default.Version = gosnmp.Version2c;
	gosnmp.Default.ExponentialTimeout = false;
	gosnmp.Default.Timeout = time.Duration(2) * time.Second
	gosnmp.Default.Retries = 2;
	// TODO(mw) set gosnmp.Default.Timeout, Retries, Community, Port from ARGV
}

/**** Helper functions ****************************************************************/

// fix_linklocal() takes an IP address «addr» and returns the same IP address
// with "%zone" attached if it is an IPv6LL address that's missing the zone
// qualifier, and returns «addr» unchanged otherwise.
func fix_linklocal(addr string) string {
    if ip := net.ParseIP(addr); ip.IsLinkLocalUnicast() {
        return ip.String() + "%" + ARGV.netif_link_local_ipv6
    }
    return addr
}

// snmp_connect() creates a handler and connects to the SNMP server «host».
// Returns «handler» in case of success and «err» in case of an error.
func snmp_connect(host string) (handler gosnmp.Handler, err error) {
	handler = gosnmp.NewHandler()
	handler.SetTarget(fix_linklocal(host))
	handler.SetLogger(gosnmp.Default.Logger)
	handler.SetTimeout(20*time.Second) // FIXME(mw) SNMP timeout should be configurable. Microsens Switch takes up to 17 seconds to send all data, which is extremely slow.
	err = handler.Connect()
	return
}

// snmp_bulkwalk() works around a gosnmp 1.37.0 bug with requesting OIDs with
// trailing dots. This function removes potential trailing dots from OIDs and
// performs the BulkWalk with handler «snmp» on OID «oid», calling «walkFn» on
// every PDU received.
//
// Returns nil in case of success, or an error.
//
// For the gosnmp issue see https://github.com/gosnmp/gosnmp/issues/480
func snmp_bulkwalk(snmp gosnmp.Handler, oid string, walkFn gosnmp.WalkFunc) error {
	return snmp.BulkWalk(strings.TrimSuffix(oid, "."), walkFn)
}

// snmp_print() prints an SNMP PDU «dataUnit» in a somewhat human readable
// format.
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

// snmp_cut() returns whether «suboid» is an instance (i.e. substring) of «oid»,
// and if so, the suboid string with the oid prefix removed.
func snmp_cut(oid string, suboid string) (bool, string) {
	// in case oid does not have a trailing dot, add it to even the playfield
	if !strings.HasSuffix(oid, ".")    {oid    += "."}

	if strings.HasPrefix(suboid, oid) {
		return true, suboid[len(oid):]
	}
	return false, ""
}

// snmp_tostring() casts a PDU «value» that's expected to be a string as string,
// and returns it or an error «err» if the type cast fails.
func snmp_tostring(value gosnmp.SnmpPDU) (r string, err error) {
	rv, ok := value.Value.([]byte)
	if !ok {
		return "", fmt.Errorf(
			"Invalid SNMP response for %s, string expected, got (%s) %s",
			value.Name, value.Type.String(), value.Value)
	}
	r = string(rv)
	return
}

// snmp_toint() casts a PDU «value» that's expected to be an int as an int, and
// returns it or an error «err» if the type cast fails.
func snmp_toint(v gosnmp.SnmpPDU) (r int, err error) {
	r, ok := v.Value.(int)
	if !ok {
		return -1, fmt.Errorf(
			"Invalid SNMP response for %s, int expected, got (%s) %s",
			v.Name, v.Type.String(), v.Value)
	}
	return
}

// snmp_oid_cutval cuts a value out of the middle of an OID/SubOID «oid» and
// returns it, if its arguments don't match the «expected» number of OID
// subindexes it returns an error. On success, it returns the OID subindex «num»
// instead.
//
// Example:
//   snmp_oid_cutval(".0.101.1", 3, 1)
//   => 101, nil
func snmp_oid_cutval(oid string, expected int, num int) (int, error) {
	s := strings.Split(strings.Trim(oid, "."), ".")
	received := len(s)
	if expected < num {expected = num}
	if received != expected {
		return -1,
			fmt.Errorf(
				"SNMP: OID (%s) contained unexpected sequence of index integers (expected %d, got %d)",
				oid, expected, received)
	}
	iv, err := strconv.Atoi(s[num])
	if err != nil {return -1, err}

	return iv, nil
}

/**** Constants ***********************************************************************/

// SNMP LLDP OIDs, the poor man's MIB.
//
// In this file, S_ is short for SNMP, the names of the constants and the OID
// mapping are sourced from the LLDP-MIB as published by the IEEE. gosnmp does
// not support parsing MIBs (and it doesn't really need to, either), so this
// block declares all SNMP OIDs used by topologyd as constants. See the
// corresponding MIB document for more information on these OIDs and how e.g.
// table entries are numbered for an item in question.
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

	// SNMP OIDs for obtaining the STP port state - from BRIDGE-MIB
	S_STPPORTSTATE = ".1.3.6.1.2.1.17.2.15.1.3";
)

// TODO(mw) wishful thinking that we can query only these and gain
// performance...
/*
 func _snmp_oids_we_care_about() []string {
 	return []string{
 		S_REMCHASSISIDSUBTYPE, S_REMCHASSISID, S_REMPORTIDSUBTYPE, S_REMPORTID,
 		S_REMSYSNAME, S_REMSYSDESC, S_REMSYSMANADDRSUBTYPE, S_REMSYSMANADDR,
 	}
 }
*/

// TODO(mw) SNMP interface OIDs for the local interfaces of an SNMP-capable
// device — do we care about these later, perhaps?
/* const (

        "ifnumber": ".1.3.6.1.2.1.2.1.",
        "ifdesc": ".1.3.6.1.2.1.2.2.1.2.",
        "ifmtu": "1.3.6.1.2.1.2.2.1.4",
        "ifspeed": ".1.3.6.1.2.1.2.2.1.5.",
        "ifmac": ".1.3.6.1.2.1.2.2.1.6.",
        "ifname": ".1.3.6.1.2.1.31.1.1.1.1.",
        "ifalias": ".1.3.6.1.2.1.31.1.1.1.18."
        )

These would be useful with a function that can look up a remote SNMP host's
chassis value, similarly to what we do with nodes running topologyd by querying
`lldpcli show chassis` remotely from their topologyd. However, this is currently
not used anywhere, and was not deemed necessary.
*/

// An enum type for SNMP-LLDP Port ID, as defined in the LLDP-MIB.
type S_LldpPortIdSubtype int
const (
	S_InterfaceAlias S_LldpPortIdSubtype = iota + 1
	S_PortComponent
	S_MacAddress
	S_NetworkAddress
	S_InterfaceName
	S_AgentCircuitId
	S_Local
)

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

// snmp_collect_locport_data() is the callback routine for collecting the data on
// network ports in a BulkWalk request. Receives «dataUnit» from gosnmp,
// «ports» from the closure calling it to store data in. Returns «err» on error.
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

// snmp_collect_neighbors() is the callback routine for collecting LLDP
// neighbors from an SNMP host. Receives «dataUnit» from gosnmp, «ports» from a
// previous SNMP LocPort lookup, isMicrosens from a simple check against the
// peer's MAC address to work around Microsens' firmware SNMP issues and stores
// its results in «neighbors». Returns «err» on error.
func snmp_collect_neighbors(dataUnit gosnmp.SnmpPDU, neighbors map[int]Neighbor, ports PortDataMap, isMicrosens bool) (err error) {
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
			n.IdType = IDTYPE_MAC
		} else if idtype == 6 {
			n.IdType = IDTYPE_IFNAME
		} else if idtype == 7 {
			n.IdType = IDTYPE_LOCAL
		} else { /* anything else is not supported right now */
			n.IdType = IDTYPE_UNKNOWN
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
		// FIXME(mw) this should be assigned in here?
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
		// As this isn't stored anywhere, there isn't much point retrieving it.
		// We're parsing the management address as both IPv4 and IPv6 below and
		// if that doesn't work out then we won't be friends.
	} else if is,idx = snmp_cut(S_REMSYSMANADDR, dataUnit.Name); is {
		// Seems at least Mikrotik's SNMP implementation  only reports one IP
		// address here? Kind of nasty when there's multiple addresses assigned
		// and we're interested in one particular address family (IPv6 in our
		// case). Also in case there's more than one neighbor host, only one
		// will have its MgmtIP returned.

		// Since reporting MgmtIP addresses is broken in microsens' firmware
		// work around it by skipping this record if it originates from a
		// microsens machine
		if isMicrosens {return}

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
    if neigh, found := neighbors[iidx]; iidx != 0 && is && found {
		// FIXME(mw) is it always the last value, or only on microsens??!? check MIB and other switch impl
		port, found := ports[iidx]
		if !found {
			return fmt.Errorf("Can't find neighbor port %d although it should be there", iidx)
		}
		neigh.SourceIface = port.PortDesc
		neighbors[iidx] = neigh
	}

	return nil
}

// log_snmp() checks if SNMP verbose logging is enabled via ARGV. In this case,
// it prints a formatted message «format», also passing on optional «arg...»
// arguments to Printf.
func log_snmp(format string, arg... interface{}) {
    if ARGV.snmp_verbose {
        log.Printf(format, arg...)
    }
}

// snmp_get_node_locport_data() queries the S_LOCPORT table from the SNMP node
// «host», returns the PortData «ret» containing the details of the remote
// host's network ports keyed by the port identifiers or «err» on error.
//
// Example return value on a microsens switch (in %+v format):
//   map[
//       101:{PortNum:101 PortIDSubtype:5 PortID:1/1 PortDesc:Port 1}
//       102:{PortNum:102 PortIDSubtype:5 PortID:1/2 PortDesc:Port 2}
//       103:{PortNum:103 PortIDSubtype:5 PortID:1/3 PortDesc:Port 3}
//       104:{PortNum:104 PortIDSubtype:5 PortID:1/4 PortDesc:Port 4}
//       105:{PortNum:105 PortIDSubtype:5 PortID:1/5 PortDesc:Uplink (Port 5)}
//       106:{PortNum:106 PortIDSubtype:5 PortID:1/6 PortDesc:Downlink (Port 6)}
//   ]
func snmp_get_node_locport_data(host string) (ret PortDataMap, err error) {
	log_snmp("=> Entering SNMP/LocPort Disco")
    ret, err = snmp_get_node_locport_data_(host)
	log_snmp("<= Leaving SNMP/LocPort Disco")
	return
}

// snmp_get_node_locport_data_() is the internal function of
// snmp_get_node_locport_data(). Takes the same parameters but actually performs
// the work.
func snmp_get_node_locport_data_(host string) (ret PortDataMap, err error) {
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
		return nil, err
	}

	return
}

// snmp_lookup_neighbors() queries «host» for its LLDP neighbors via SNMP.
// Returns LLDP neighbors «res», or «err» in case of error.
//
// Example return value on microsens switch (in %+v format):
//  {
//    ns:[
//    {
//      Identifier:b6:fe:ef:00:00:28
//      IdType:1
//      Descr:DET Wayland dunfell-7.0-29-g08713e0 (dunfell) Linux 5.4.24 #1 SMP PREEMPT Thu Oct 7 08:39:19 UTC 2021 aarch64
//      Hostname:dc3500
//      SourceIface:Port 4
//      SourceNeighbor:fe80::260:a7ff:fe0d:989b
//      MgmtIPs:[fe80::b4fe:efff:fe00:28]
//      Origin:2
//    }
//    {
//      Identifier:b6:fe:ef:00:00:29
//      IdType:1
//      Descr:DET Wayland dunfell-7.0-29-g08713e0 (dunfell) Linux 5.4.24 #1 SMP PREEMPT Thu Oct 7 08:39:19 UTC 2021 aarch64
//      Hostname:dc3500
//      SourceIface:Port 3
//      SourceNeighbor:fe80::260:a7ff:fe0d:989b
//      MgmtIPs:[fe80::b4fe:efff:fe00:29]
//      Origin:2
//    }]
//    origin:2
//    ip:fe80::260:a7ff:fe0d:989b
//    mac:
//    stp:map[]
//    snmp_locportdata: See snmp_get_node_locport_data() example
//  }
func snmp_lookup_neighbors(host string) (res NeighborLookupResult, err error) {
	log_snmp("=> Entering SNMP")
	res, err = snmp_lookup_neighbors_(host)
	log.Printf("%+v", res)
	log_snmp("<= Leaving SNMP")
	return
}

// snmp_lookup_neighbors_() is the internal function of snmp_lookup_neighbors().
// Takes the same parameters but actually performs the work.
func snmp_lookup_neighbors_(host string) (res NeighborLookupResult, err error) {
	// FIXME(mw) it would be nice here go use GetBulk rather than BulkWalk to
	// only fetch _snmp_oids_we_care_about() to save some traffic, on the other
	// hand there is a minimum amount of fields in 1.0.8802 we don't care about
	// and the entire lookup finishes in 2 SNMP requests on the test setup.
	snmp, err := snmp_connect(host)
	if err != nil {return}
	ports, err := snmp_get_node_locport_data(host)
	if err != nil {return}

	// Maps SNMP indexes of LLDP-MIB::lldpRemEntry to corresponding Neighbor
	// struct while the individual fields are being gathered
	neighbors := make(map[int]Neighbor)
	isMicrosens := ndp_is_microsens(host)

	if err = snmp_bulkwalk(snmp, S_REM, func(pdu gosnmp.SnmpPDU) error {
		// closure that captures the neighbors map to pass values out
		return snmp_collect_neighbors(pdu, neighbors, ports, isMicrosens)
	}); err != nil {
		log.Println("SNMP lookup aborted due to error:", err)
		return
	}

	// TODO(mw) MikroTik RouterOS does not support returning multiple MgmtIP
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
		if v.IsEmpty() {continue} // a port with nothing attached
		if len(v.MgmtIPs) == 0 && v.IdType == IDTYPE_MAC {
			// This is mainly a workaround for Microsens Switches (6-Port GBE
			// Micro Switch G6 POE+, Firmware version 12.8.0a) which have broken
			// MgmtIP support in their SNMP/LLDP stack and do not pass MgmtIP
			// addresses out via SNMP, so get them from the NDP table if
			// possible.
			//
			// By default, Linux bridge interfaces get a random MAC address
			// assigned. In this case, this code will break, so you have to
			// manually ensure that the Linux machine in question has the same
			// MAC as ChassisID as well as MAC address on br0.
			go icmp6_ping_broadcast(ARGV.netif_link_local_ipv6)
			time.Sleep(200*time.Millisecond)
			vv, err := ndp_get_neighbors(ARGV.netif_link_local_ipv6)
			if err == nil {
				if ip, found := vv[v.Identifier]; found  {
					v.MgmtIPs = ip
				}
			}
		}
		v.Origin         = ORIGIN_SNMP
		v.SourceNeighbor = host
		ret = append(ret, v)
	}

	// wrap result in struct NeighborLookupResult
	res = NeighborLookupResult{
		ns:               ret,
		origin:           ORIGIN_SNMP,
		ip:               host,
		snmp_locportdata: ports,
	}

	return
}

// snmp_get_node_stp_port_state() is the callback routine for collecting STP
// port states from an SNMP host. Receives «dataUnit» from gosnmp,
// adding entries to the «stp_states» table, passing them back to the calling
// closure. Returns «err» on error.
func snmp_collect_stp_data(pdu gosnmp.SnmpPDU, stp_states map[int]int) (err error) {
	var iidx int
	if is,idx := snmp_cut(S_STPPORTSTATE, pdu.Name); is {
		iidx, err = strconv.Atoi(idx)
		if err != nil {return}
		if stp_states[iidx], err = snmp_toint(pdu); err != nil {return}
		//if n.SourceIface, err = snmp_toint(pdu); err != nil {return}
		snmp_print(pdu)
	} else {
		log.Println("BUG this isn't supposed to be here", pdu)
	}

	return
}

// (*NeighborLookupResult).snmp_get_node_stp_port_state() queries the STP port
// state from an SNMP host after its LLDP neighbors and local port information
// have been queried. Returns «ret» if successful or nil on error.
//
// Example return value on microsens switch (in %+v format):
//
//   map[
//     Downlink (Port 6):forwarding
//     Port 1:forwarding
//     Port 2:forwarding
//     Port 3:forwarding
//     Port 4:forwarding
//     Uplink (Port 5):forwarding
//   ]
func (nr *NeighborLookupResult) snmp_get_node_stp_port_state() (ret PortToStateMap) {
	snmp, err := snmp_connect(nr.ip)
	if err != nil {
		log.Printf("snmp connection failed: %s: %s", nr.ip, err)
		return nil
	}

	stp_states := make(map[int]int)
	if err = snmp_bulkwalk(snmp, S_STPPORTSTATE, func(pdu gosnmp.SnmpPDU) error {
		// closure that captures the neighbors map to pass values out
		return snmp_collect_stp_data(pdu, stp_states)
	}); err != nil {
		log.Println("SNMP lookup aborted due to error:", err)
		return
	}

	// See http://oidref.com/1.3.6.1.2.1.17.2.15.1.3
	mapping := map[int]PortState {
		// This mapping is based on CISCO's mapping of STP states to RSTP states.
		// https://www.cisco.com/c/en/us/td/docs/optical/15000r8_5/ethernet/454/guide/r85ether/r85swstp.html#wp1127767
		1: Discarding,       // disabled(1),
		2: Discarding,       // blocking(2),
		3: Discarding,       // listening(3),
		4: Learning,         // learning(4),
		5: Forwarding,       // forwarding(5),
		6: Unknown,          // broken(6)
	}

	ret = make(PortToStateMap)
	// Uses the port's PortDesc description as the port name because it's also
	// used in the LLDP Neighbor's SourcePort information and because "Port 3"
	// is a lot more comprehensive than random indexes like 103.
	for k,v := range stp_states {
		mapv, ok := mapping[v]
		if !ok {
			log.Println("STP: remote SNMP server returned invalid value")
			mapv = Unknown
		}
		key := nr.snmp_locportdata[k].PortDesc // assumes PortDesc is unique
		ret[key] = mapv
	}

	return
}
