package main

import (
	//"fmt"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

func snmp_init() {
	log.Println("snmp_init")

	// verbose logging? always on for now
	//gosnmp.Default.Logger  = gosnmp.NewLogger(log.Default())
	gosnmp.Default.Version = gosnmp.Version2c;
	gosnmp.Default.ExponentialTimeout = false;
	gosnmp.Default.Timeout = time.Duration(2) * time.Second
	gosnmp.Default.Retries = 2;
	// TODO set gosnmp.Default.Timeout, Retries, Community, Port from ARGV
}

func snmp_make_handler(host string) (snmp gosnmp.Handler) {
	snmp = gosnmp.NewHandler()
	snmp.SetTarget(host)
	snmp.SetLogger(gosnmp.Default.Logger)
	return
}

// SNMP LLDP OIDs. Poor man's MIB :)
const (
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

func _snmp_oids_we_care_about() []string {
	return []string{
		S_REMCHASSISIDSUBTYPE, S_REMCHASSISID, S_REMPORTIDSUBTYPE, S_REMPORTID,
		S_REMSYSNAME, S_REMSYSDESC, S_REMSYSMANADDRSUBTYPE, S_REMSYSMANADDR,
	}
}

// SNMP interface OID's
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

func snmp_print(dataUnit gosnmp.SnmpPDU) {
	if dataUnit.Type == gosnmp.OctetString {
		bytes := dataUnit.Value.([]byte)
		log.Printf("%s (%s) = %s", dataUnit.Name, dataUnit.Type.String(), string(bytes))
	} else if dataUnit.Type == gosnmp.Integer {
		log.Printf("%s (%s) = %d", dataUnit.Name, dataUnit.Type.String(), dataUnit.Value.(int))
	} else {
		log.Println(dataUnit)
	}
}

func snmp_cut(oid string, suboid string) (bool, string) {
	if strings.HasPrefix(suboid, oid) {
		return true, suboid[len(oid):]
	}
	return false, ""
}

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

func snmp_toint(v gosnmp.SnmpPDU) (r int, err error) {
	r, ok := v.Value.(int)
	if !ok {
		return -1, fmt.Errorf(
			"Invalid SNMP response for %s, int expected, got (%s) %s",
			v.Name, v.Type.String(), v.Value)
	}
	return
}

// wow, lots of boilerplate and no nice way to express it!
func snmp_collect_neighbors(dataUnit gosnmp.SnmpPDU, neighbors map[string]Neighbor) (err error) {
	n := Neighbor{}

	//snmp_print(dataUnit)

	if is,idx := snmp_cut(S_REMCHASSISIDSUBTYPE, dataUnit.Name); is {
		/* possible values for Chassis ID Subtype (see LLDP-MIB) */
		/* 'chassisComponent(1)'
		 * 'interfaceAlias(2)'
		 * 'portComponent(3)'
		 * 'macAddress(4)'
		 * 'networkAddress(5)'
		 * 'interfaceName(6)'
		 * 'local(7)'
 		 */
		n, _ = neighbors[idx]

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
		neighbors[idx] = n
	} else if is,idx := snmp_cut(S_REMCHASSISID, dataUnit.Name); is {
		n, _ = neighbors[idx]
		if n.Identifier, err = snmp_tostring(dataUnit); err != nil {return}
		neighbors[idx] = n
	} else if is,_ := snmp_cut(S_REMPORTIDSUBTYPE, dataUnit.Name); is {
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
		idtype, err := snmp_toint(dataUnit)
		if err != nil {return err}

		if idtype != 5 {
			log.Println("Eeep! SNMP Neighbor reported strange Port ID type:", idtype)
		}
	} else if is,idx := snmp_cut(S_REMPORTID, dataUnit.Name); is {
		n, _ = neighbors[idx]
		if n.SourceIface, err = snmp_tostring(dataUnit); err != nil {return}
		neighbors[idx] = n
	} else if is,idx := snmp_cut(S_REMSYSNAME, dataUnit.Name); is {
		n, _ = neighbors[idx]
		if n.Hostname, err = snmp_tostring(dataUnit); err != nil {return}
		neighbors[idx] = n
	} else if is,idx := snmp_cut(S_REMSYSDESC, dataUnit.Name); is {
		n, _ = neighbors[idx]
		if n.Descr, err = snmp_tostring(dataUnit); err != nil {return}
		neighbors[idx] = n

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

	} else if is,_:= snmp_cut(S_REMSYSMANADDRSUBTYPE, dataUnit.Name); is {
		/* SNMP is showing its age here. We support 1 and 2 here, everything
		   else can rot in hell. */
		/* 'ipV4(1)'
           'ipV6(2)' */
		idtype, err := snmp_toint(dataUnit)
		if err != nil {return err}
		if idtype != 1 && idtype != 2 {
			log.Println("Eeep! SNMP Neighbor reported strange Management IP address family type:", idtype)
		}
		// As this isn't stored anywhere, there isn't much point retrieving it.
		// We're parsing the management address as both IPv4 and IPv6 below and
		// if that doesn't work out then we won't be friends.
	} else if is,idx := snmp_cut(S_REMSYSMANADDR, dataUnit.Name); is {
		// Seems at least Mikrotik's SNMP implementation  only reports one IP
		// address here? Kind of nasty when there's multiple addresses assigned
		// and we're interested in one particular address family (IPv6 in our
		// case) but such is life.
		n, _ = neighbors[idx]

		var ip string
		if ip, err = snmp_tostring(dataUnit); err != nil {return}

		n.MgmtIPs = append(n.MgmtIPs, ip)
		neighbors[idx] = n
	}

	return nil
}

// Discover LLDP neighbors queried from a neighbor node via SNMP
func snmp_lookup_neighbors(host string) (ret []Neighbor, err error) {
	// XXX it would be nice here go use GetBulk rather than BulkWalk to only
	// fetch _snmp_oids_we_care_about() to save some traffic, on the other
	// hand there is a minimum amount of fields in 1.0.8802 we don't care about
	// and the entire lookup finishes in 2 SNMP requests on the test setup.
	snmp := snmp_make_handler(host)
	err = snmp.Connect()
	if err != nil {return}

	// Maps SNMP indexes of LLDP-MIB::lldpRemEntry to corresponding Neighbor
	// struct while the individual fields are being gathered
	neighbors := make(map[string]Neighbor)
	if err = snmp.BulkWalk("1.0.8802", func(pdu gosnmp.SnmpPDU) error {
		// closure that captures the neighbors map to pass values out
		return snmp_collect_neighbors(pdu, neighbors)
	}); err != nil {
		log.Println("SNMP lookup aborted due to error:", err)
		return nil, err
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
	for _,v := range neighbors {
		v.SourceNeighbor = host
		ret = append(ret, v)
		log.Println(v)
	}

	log.Println(ret)
	return
}
