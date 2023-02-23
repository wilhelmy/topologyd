package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
    "net"
	"net/http"
	"strings"
    "time"
	"jgf"
)

/**** Commandline arguments section ***************************************************/

var ARGV struct {
    // Listen port for HTTP queries
    port                  int

    // On dc3500, this is br0. For development on PC, it's the network interface
    // connected to the DC3500 LAN.
    netif_link_local_ipv6 string

    // Set to an IP address to use as a starting point. In production, this
    // would be "localhost". For development, it can be any machine running
    // topologyd.
    start_host            string

    // Special treatment for dc3500 hostname (other names are logged specially).
    host_prefix           string

    // Preallocate this many entries in the hashtable. Can be tuned in the
    // future if networks are larger in practice.
    nodes_prealloc        int

    // HTTP request timeout
    http_timeout          time.Duration

    // Prefer link local addresses over other type of MgmtIP returned via LLDP
    prefer_link_local     bool

    // Prefer IPv6 addresses over IPv4 MgmtIPs returned via LLDP
    prefer_ipv6           bool
}


/**** Debug section *******************************************************************/
const dbg_http_query_verbose = false
const dbg_gather_neighbors_verbose = true

/**** Constants ***********************************************************************/
const lldp_neighbor_path = "/lldp/neighbors"
const lldp_chassis_path  = "/lldp/chassis"
const stp_port_state_path= "/stp/port_state"
const graphviz_path      = "/topology/graphviz"
const jgf_path           = "/topology/jgf"

/**** HTTP code ***********************************************************************/
// Handler function for incoming HTTP requests to query the local node's
// chassis or neighbor info
func handle_lldp_request(w http.ResponseWriter, req *http.Request) {
    log.Printf("Received HTTP GET from %s for %s", req.RemoteAddr, req.URL.Path)
    reqName := req.URL.Path[6:] // cut leading /lldp/
    switch reqName {
    case "neighbors", "chassis":
        break
    default: // method not whitelisted
        w.WriteHeader(http.StatusForbidden)
        log.Printf("Request for '%s' denied\n", req.URL.Path)
        return
    }

    res, err := run_lldpcli_show(reqName)
    if err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        log.Printf("Request for '%s': %s\n", req.URL.Path, err)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    if _, err := w.Write(res); err != nil {
        log.Printf("Request for '%s' caused failure %s\n", req.URL.Path, err)
    }
}

// Handler function for incoming HTTP requests to resolve the network topology
// and return the result in graphviz format
func handle_graphviz_request(w http.ResponseWriter, req *http.Request) {
    start, neighbors := gather_neighbors_from_nodes()

    if neighbors == nil || start == "" {
        w.WriteHeader(http.StatusInternalServerError)
        log.Printf("Request for '%s': Internal Server Error, LLDP topology resolution failed.", req.URL.Path)
        return
    }

    //g := assemble_graph(start, neighbors)
    res := generate_graphviz(start, neighbors)

    // MIME type according to https://www.iana.org/assignments/media-types/text/vnd.graphviz
    w.Header().Set("Content-Type", "text/vnd.graphviz")
    if _, err := w.Write(res.Bytes()); err != nil {
        log.Printf("Request for '%s' caused failure %s\n", req.URL.Path, err)
    }
}

// Handler function for incoming HTTP requests to resolve the network topology
// and return the result in JSON Graph Format
func handle_jgf_request(w http.ResponseWriter, req *http.Request) {
    // XXX: deduplicate code between this and graphviz handler the next time
    // you touch either of them

    start, neighbors := gather_neighbors_from_nodes()

    if neighbors == nil || start == "" {
        w.WriteHeader(http.StatusInternalServerError)
        log.Printf("Request for '%s': Internal Server Error, LLDP topology resolution failed.", req.URL.Path)
        return
    }

    res := generate_json_graph(start, neighbors)

    // MIME type according to JGF Specification
    w.Header().Set("Content-Type", jgf.MIME_TYPE)
    if _, err := w.Write(res.Bytes()); err != nil {
        log.Printf("Request for '%s' caused failure %s\n", req.URL.Path, err)
    }
}

// Handler function for incoming HTTP queries to the STP API
func handle_stp_request(w http.ResponseWriter, req *http.Request) {
    res := STP_get_port_state_json(ARGV.netif_link_local_ipv6)

    if len(res) == 0 {
        log.Printf("Request for '%s': Internal Server Error, "+
            "see previous error message for reason.", req.URL.Path)
        w.WriteHeader(http.StatusInternalServerError)
        return
    }

    w.Header().Set("Content-Type", "application/json")
    if _, err := w.Write(res); err != nil {
        log.Printf("Request for '%s' caused failure %s\n", req.URL.Path, err)
    }

    return
}

// Send HTTP GET requests to specified node, logs errors and discards malformed
// responses to keep the rest of the logic clean - expects JSON response from
// Server
func http_get(host string, path string) []byte {
    if host == "" {
        log.Printf("http_get called with empty host")
        return []byte{}
    }
    var url string
    zone := ""
    if ip := net.ParseIP(host); ip.IsLinkLocalUnicast() {
        // link local IPv6 address, need to append %netif, otherwise it can't be used
        zone = "%25" + ARGV.netif_link_local_ipv6 //%25 = %
    }
    if strings.Index(host, ":") >= 0 {
        // IPv6 addresses need to be wrapped in angle brackets
        url = fmt.Sprintf("http://[%s%s]:%d%s", host, zone, ARGV.port, path)
    } else {
        url = fmt.Sprintf("http://%s:%d%s", host, ARGV.port, path)
    }
    client := http.Client{
        Timeout: ARGV.http_timeout,
    }
    resp, err := client.Get(url) // send request
    if err != nil {
        log.Printf("Error querying %s: %s\n", url, err)
        return nil
    } else if dbg_http_query_verbose {
        log.Printf("HTTP response for GET %s: %v\n", url, resp)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        log.Printf("HTTP GET %s returned code %d %s: %v\n",
            url, resp.StatusCode, resp.Status, resp)
        return nil
    }

    contentType := resp.Header.Get("Content-type")
    if contentType != "application/json" {
        log.Printf("HTTP GET %s did not return JSON: %v\n", url, resp)
        return nil
    }

    // read response body
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        log.Printf("Error reading response body for GET %s: %s\n", url, err)
        return nil
    } else if dbg_http_query_verbose {
        log.Printf("Body: %s\n", body)
    }
    return body
}

/**** LLDP-HTTP interface *************************************************************/
// the more wrappers, the better, right?
func http_get_node_neighbor_info(host string) ([]Neighbor, error) {
    if host == "" {
        return nil, fmt.Errorf("http_get_node_neighbor_info called on empty string")
    }

    data := http_get(host, lldp_neighbor_path)
    if data == nil {
        return nil, fmt.Errorf("HTTP GET %s on '%s' failed", lldp_neighbor_path, host)
    }

    // parse result as JSON
    neighbors, err := Parse_lldpcli_neighbors_output(data)
    if err != nil {
        log.Print(err)
    }

    return neighbors, err
}

// HTTP GET on the chassis URL for a given host, pull MgmtIP out of the chassis
// data which was returned
func http_get_host_mgmt_ip(host string) (ret string) {
    data := http_get(host, lldp_chassis_path)
    if data == nil { return }

    chassis, err := lldp_parse_chassis_data(data)
    if err != nil {
        log.Println(err)
        return
    }

    ret, err = get_suitable_mgmt_ip(chassis.MgmtIPs)
    if err != nil {
        log.Printf("Error getting MgmtIP: %s %+v", err, chassis)
    }
    return
}

// Queries STP link state from host
func http_get_node_stp_link_state(host string) (ret PortToStateMap) {
    data := http_get(host, stp_port_state_path)
    if data == nil { return nil }

    ret = STP_parse_port_state_json(data)
    return
}

// return text surrounded by terminal attribute for enable/disable bold font
func bold(x string) string {
    return "\033[1;1m" + x + "\033[0;0m"
}

// Map keyed by primary MgmtIP to that node's Neighbors
type NodeMap map[string]NeighborSlice

func dbg_gather(format string, arg... interface{}) {
    if dbg_gather_neighbors_verbose {
        log.Printf(format, arg...)
    }
}

// Send HTTP GET requests to obtain neighbors from hosts and handle errors
func get_node_neighbors(ip string) []Neighbor {
    var cur []Neighbor
    cur, err := http_get_node_neighbor_info(ip)
    if err != nil {
        log.Printf("GET neighbors from '%s': error: %s. Skipping.", ip, err)
    } else if cur == nil {
        log.Printf("GET neighbors from '%s': something is fishy, no neighbors or error returned. Skipping.", ip)
    }
    return cur
}

// Crawl the entire network for LLDP neighbors and STP state, returning a Map of
// node name (== management IP) to NeighborSource, which in turn contains
// interface name, STP state and neighbors found on the interface.
func gather_neighbors_from_nodes() (string, *NodeMap) {
    // hashmap keyed by MgmtIP addresses, also used for tracking whether or not
    // a node has been queried before by setting its value to nil
    neighbors := make(NodeMap, ARGV.nodes_prealloc)

    dbg_gather("== Begin gathering neighbors ==")
    start:= http_get_host_mgmt_ip(ARGV.start_host)
    ip   := start
    todo := []string{ ip }
    iter := 0

    for len(todo) > 0 {
        ip, todo = todo[0], todo[1:]
        iter++
        dbg_gather(bold("Processing #%d (host %s), todo list: %v"), iter, ip, todo)

        cur := get_node_neighbors(ip)
        if len(cur) < 1 {continue}

        /* TODO refactor
        // Send HTTP GET requests to obtain STP state from hosts and process the results
        stp := http_get_node_stp_link_state(ip)
        if stp == nil {
            log.Printf("GET STP state from '%s': No result,", ip)
        }
        for i := range cur {
            cur[i].LinkState = Unknown
            var found bool
            cur[i].LinkState, found = stp[cur[i].Name]
            if !found {
                log.Printf("LLDP information includes interface '%s' for which no STP information exists. Setting "+
                    "to unknown.", cur[i].Name)
            }
        }
        */
        neighbors[ip] = cur

        for i, neigh := range cur { // loop over all found neighbors
            dbg_gather("Neighbor (%d/%d): %+v", i+1, len(cur), neigh)

            newip, err := get_suitable_mgmt_ip(neigh.MgmtIPs)
            if err != nil {
                log.Printf("gather: machine %s: failed to get management IP: %s", ip, err)
                continue
            }

            // the hashtable is dual-use to prevent duplicating previously
            // looked-up todo list entries
            if _, found := neighbors[newip]; !found {
                // initialize hashtable location to nil for deduplication
                neighbors[newip] = nil
                todo = append(todo, newip)
            }
        }
    }
    dbg_gather("== End gathering neighbors ==")

    return start, &neighbors
}

func graphviz_quote_array_of_mgmt_ips(in []string) []byte {
    var buf bytes.Buffer

    for _, v := range in {
        if v != "" {
            buf.WriteString(fmt.Sprintf(" \"%s\"", v))
        }
    }

    return buf.Bytes()
}

func generate_graphviz(start string, nodes *NodeMap) *bytes.Buffer {
    var buf bytes.Buffer

    buf.WriteString("strict graph {\n")

    hostnames := make(map[string]string, len(*nodes))
    for _, v := range *nodes {
        if v == nil {continue} // XXX FIXME lol
        hostnames_k := v.get_hostnames()
        for k, v := range hostnames_k {
            hostnames[k] = v
        }
    }

    for k, v := range *nodes {
        if v == nil {
            log.Printf("Error: neighbor '%s' has nil neighbors instead "+
                "of empty list. This can mean topologyd isn't running there or "+
                "it is a bug.", k)
            continue
        }

        buf.WriteString(fmt.Sprintf("\t\"%s\" [shape=box,label=\"Machine: %s\\n%s\"]; // node\n", k, hostnames[k], k))
    }
    buf.WriteString("\n")

    for k, v := range *nodes {
        if v == nil {continue} // error already logged above
        //mgmtlink := get_neighbor_mgmt_ips_link_state(v)
        //neigh := graphviz_quote_array_of_mgmt_ip_link_states(mgmtlink)
        mgmt := v.get_mgmt_ips()
        neigh := graphviz_quote_array_of_mgmt_ips(mgmt)

        buf.WriteString(fmt.Sprintf("\t\"%s\" -- {%s }; // edge\n", k, neigh))
        /* TODO
        for _, port := range mgmtlink {
            if port.LinkState != Forwarding {
                color := [...]string{ "brown", "lightgray", "darkgreen", "black" }[port.LinkState]
                buf.WriteString(fmt.Sprintf("\t\"%s\" -- \"%s\" [color=%s]; // edge\n", k, port.MgmtIP, color))
            }
        }
        */
    }
    buf.WriteString("}\n")

    return &buf
}

/**** Main loop ***********************************************************************/
func main() {
    // add file name + line number to log output
    log.SetFlags(log.LstdFlags | log.Lshortfile)


    // handle command line flags
    flag.IntVar(      &ARGV.port,           "port",                     9090, "listen port")
    flag.IntVar(      &ARGV.nodes_prealloc, "nodes-prealloc",             32, "expected maximum number of nodes in network for memory allocation")
    flag.DurationVar( &ARGV.http_timeout,   "http-timeout",    2*time.Second, "HTTP request timeout")
    flag.StringVar(   &ARGV.start_host,     "start-host",        "localhost", "start host for topology discovery")
    flag.StringVar(   &ARGV.netif_link_local_ipv6, "netif",            "br0", "network interface to use for IPv6 LL traffic")
    flag.BoolVar(     &ARGV.prefer_link_local, "prefer-link-local",     true, "prefer link local addresses from LLDP (otherwise, use the first one found)")
    flag.BoolVar(     &ARGV.prefer_ipv6,       "prefer-ipv6",           true, "prefer IPv6 addresses reported by LLDP (otherwise, use the first one found)")
    flag.StringVar(   &ARGV.host_prefix,    "host-prefix",          "dc3500", "hostnames that don't start with this string generate a warning if found (set to '' to disable)")
    flag.Parse()

    if len(flag.Args()) > 0 {
        log.Fatalf("Error: extra arguments on commandline: %v", flag.Args())
    }

    // initialize http handlers
    http.HandleFunc(lldp_neighbor_path,  handle_lldp_request)
    http.HandleFunc(lldp_chassis_path,   handle_lldp_request)

    http.HandleFunc(stp_port_state_path, handle_stp_request)

    http.HandleFunc(graphviz_path,       handle_graphviz_request)
    http.HandleFunc(jgf_path,            handle_jgf_request)

    // start httpd
    if err := http.ListenAndServe(fmt.Sprintf(":%d", ARGV.port), nil); err != nil {
        log.Println(err)
    }
}
