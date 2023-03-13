/* main file of topologyd. Contains glue code, main logic and HTTP handling. */
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
    "sort"
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

    // Whether or not to query STP port state
    query_stp_state       bool

    // Whether or not to print the neighbors as they are gathered
    gather_verbose        bool
}


/**** Debug section *******************************************************************/
const dbg_http_query_verbose = false

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
// HTTP GET request wrapper for the LLDP neighbors URL. Returns the parsed JSON
// as a slice of struct Neighbor.
func http_get_node_neighbor_info(host string) (NeighborSlice, error) {
    if host == "" {
        return nil, fmt.Errorf("http_get_node_neighbor_info called on empty string")
    }

    data := http_get(host, lldp_neighbor_path)
    if data == nil {
        return nil, fmt.Errorf("HTTP GET %s on '%s' failed", lldp_neighbor_path, host)
    }

    // parse result as JSON
    neighbors, err := Parse_lldpcli_neighbors_output(host, data)
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

// Send HTTP GET request to obtain STP state from neighbor
func (n *Neighbor) gather_node_stp_state() (err error) {
    if (*n).PortState != nil {
        return fmt.Errorf("neighbor link state is already populated: %v", *n)
    }

    mgmtip, err := get_suitable_mgmt_ip((*n).MgmtIPs)
    if err != nil {return err}

    stp := http_get_node_stp_link_state(mgmtip)
    (*n).PortState = stp

    return nil
}

// Map keyed by primary MgmtIP to that node's Neighbors
type NodeMap map[string]NeighborSlice

// Wrapper for verbose log messages used by the neighbor gathering process
func log_gather(format string, arg... interface{}) {
    if ARGV.gather_verbose {
        log.Printf(format, arg...)
    }
}

// Send HTTP GET requests to obtain neighbors from hosts and handle errors
func get_node_neighbors(ip string) (ret NeighborSlice) {
    ret, err := http_get_node_neighbor_info(ip)
    if err != nil {
        log.Printf("GET neighbors from '%s': error: %s. Skipping.", ip, err)
    } else if ret == nil {
        log.Printf("GET neighbors from '%s': something is fishy, no neighbors or error returned. Skipping.", ip)
    }
    return
}

// Crawl the entire network for LLDP neighbors and STP state, returning a Map of
// node name (== management IP) to NeighborSource, which in turn contains
// interface name, STP state and neighbors found on the interface.
func gather_neighbors_from_nodes() (string, *NodeMap) {
    // hashmap keyed by MgmtIP addresses, also used for tracking whether or not
    // a node has been queried before by setting its value to nil
    neighbors := make(NodeMap, ARGV.nodes_prealloc)

    log_gather("== Begin gathering neighbors ==")
    start:= http_get_host_mgmt_ip(ARGV.start_host)
    ip   := start
    todo := []string{ ip }
    iter := 0

    for len(todo) > 0 {
        ip, todo = todo[0], todo[1:]
        iter++
        log_gather(bold("Processing #%d (host %s), todo list: %v"), iter, ip, todo)

        cur := get_node_neighbors(ip)
        if len(cur) < 1 {continue}

        neighbors[ip] = cur

        for i, neigh := range cur { // loop over all found neighbors
            log_gather("Neighbor (%d/%d): %+v", i+1, len(cur), neigh)

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
    log_gather("== End gathering neighbors ==")

    if ARGV.query_stp_state {
        log_gather("== Begin gathering STP state ==")
        for _, v := range neighbors {
            v.gather_stp_states()
        }
        log_gather("== End gathering STP state ==")
    }

    return start, &neighbors
}

// Given a primary MgmtIP address, find information about that host as seen by
// any one of its peers that knows about it
func (ns *NodeMap) mirror_mirror_on_the_wall(node string) Neighbor {
    node_neighbors := (*ns)[node]
    if len(node_neighbors) == 0 {return Neighbor{}} // a hermit has no neighbors

    for _, peer := range node_neighbors {
        if peer.IsEmpty() {continue} // I never introduced myself when I moved in
        peer_ip, err := get_suitable_mgmt_ip(peer.MgmtIPs)
        if err != nil {continue}
        peer_neighbors := (*ns)[peer_ip]

        mirror_image, err := peer_neighbors.find_neighbor_by_ip(node)
        if err != nil || mirror_image.IsEmpty() {continue}

        return mirror_image
    }
    return Neighbor{}
}

// Given 2 neighbors, iff they're directly connected, returns the "inferior"
// PortState (i.e. smaller value of the PortState enum) of the two.
func (ns *NodeMap) stp_link_state(node string, peer string) PortState {
    // all neighbors reported by node and peer
    node_neighbors := (*ns)[node]
    peer_neighbors := (*ns)[peer]

    // find the Neighbor struct reported by each for the other
    n1, _ := node_neighbors.find_neighbor_by_ip(peer)
    n2, _ := peer_neighbors.find_neighbor_by_ip(node)

    // this synchronization errors could occur if topologyd isn't running or
    // mstpd doesn't work right
    if n2.IsEmpty() {
        log.Printf("Warning: no reply from peer %s reported by node %s as %+v. Is mstpd/topologyd running?", node, peer, n1)
        return Unknown
    }
    if n1.IsEmpty() {
        log.Printf("Warning: no reply from node %s reported by peer %s as %+v. Is mstpd/topologyd running?", peer, node, n2)
        return Unknown
    }

    // FIXME if the same neighbor can be seen on multiple interfaces, this
    // breaks. On a ring topology, the only case is two nodes connected in a
    // ring. Evaluate under which other circumstances this can happen in other
    // topologies.
    if1 := n1.SourceIface
    if2 := n2.SourceIface

    if ps1,  ps2 := n1.PortState[if2], n2.PortState[if1];
       ps1 < ps2 {
        return ps1
    } else {
        return ps2
    }
}

// generates graphviz output view for the graph
func generate_graphviz(start string, nodes *NodeMap) *bytes.Buffer {
    var buf bytes.Buffer

    jgf := generate_jgf_graph(start, nodes)

    buf.WriteString("strict graph {\n")

    // generate output for all individual nodes
    lines := make([]string, len(jgf.Nodes))
    for i, node := range jgf.Nodes {
        meta := jgf_node_get_metadata(&node)
        text := fmt.Sprintf("\t\"%s\" [shape=box,label=\""+
            "Hostname: %s\\n"+
            "%s: %s\\n"+
            "IP: %s\"]",
            node.Label, meta.Hostname, meta.IdType, meta.Identifier, node.Label)
        lines[i] = text
    }
    // sort output to make it look predictably
    lines = sort.StringSlice(lines)
    // join all together and append to buffer
    buf.WriteString(strings.Join(lines, "\n"))
    buf.WriteString("\n")

    // generate output for all individual edges
    lines = make([]string, len(jgf.Edges))
    for i, edge := range jgf.Edges {
        // node connectivity status is displayed using different colors
        color := "cyan" // well-visible fallback if STP is disabled
        if ARGV.query_stp_state {
            rel, err := ParsePortState(edge.Relation)
            if err != nil {rel = Unknown}
            color = rel.LinkColor()
        }
        lines[i] = fmt.Sprintf("\t\"%s\" -- \"%s\" [color=\"%s\"]",
            edge.Source, edge.Target, color)
    }
    // sort output to make it look predictably
    lines = sort.StringSlice(lines)
    // join all together and append to buffer
    buf.WriteString(strings.Join(lines, "\n"))
    buf.WriteString("\n")

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
    flag.BoolVar(     &ARGV.query_stp_state,   "query-stp-state",       true, "enable querying STP state")
    flag.BoolVar(     &ARGV.gather_verbose,    "gather-verbose",        true, "whether or not to print neighbors as they are gathered")
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
