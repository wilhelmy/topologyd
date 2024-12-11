// main file of topologyd. Contains glue code, main logic and HTTP handling.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"jgf"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"
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

    // Whether or not to print snmp lookups verbosely
    snmp_verbose          bool

    // whether or not to gather node neighbors via snmp if the node doesn't
    // respond to a topologyd API request
    gather_snmp           bool

    // directory where data is stored
    data_dir              string

    // how often to check up on neighbors to identify topology changes
    monitoring_freq       time.Duration
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

var http_handlers = make(map[string]http.HandlerFunc)
// init is called once at program start before main()
func init() {
    http_handlers [lldp_neighbor_path]  = handle_lldp_request
    http_handlers [lldp_chassis_path]   = handle_lldp_request
    http_handlers [stp_port_state_path] = handle_stp_request
    http_handlers [graphviz_path]       = handle_graphviz_request
    http_handlers [jgf_path]            = handle_jgf_request
}

// Handler function for incoming HTTP requests to query the local node's
// chassis or neighbor info
func handle_lldp_request(w http.ResponseWriter, req *http.Request) {
    log.Printf("Received HTTP GET from %s for %s", req.RemoteAddr, req.URL.Path)
    reqName := strings.TrimPrefix(req.URL.Path, "/lldp/")
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

    res := jgf_generate_json(start, neighbors)

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
}

// Given an IPv6 address, returns the same IPv6 address with %zone attached if
// required
func fix_linklocal(host string) string {
    if ip := net.ParseIP(host); ip.IsLinkLocalUnicast() {
        return ip.String() + "%" + ARGV.netif_link_local_ipv6
    }
    return host
}

// http_make_url turns a host and path into a full URL by adding IPv6LL zone and
// port number, and wrapping IPv6 addresses in angle brackets
func http_make_url(host string, path string) (url string) {
    port := ARGV.port
    zone := ""
    if ip := net.ParseIP(host); ip.IsLinkLocalUnicast() {
        // link local IPv6 address, need to append %netif, otherwise it can't be used
        zone = "%25" + ARGV.netif_link_local_ipv6 //%25 = %
    }
    if strings.Contains(host, ":") {
        // IPv6 addresses need to be wrapped in angle brackets
        url = fmt.Sprintf("http://[%s%s]:%d%s", host, zone, port, path)
    } else {
        url = fmt.Sprintf("http://%s:%d%s", host, port, path)
    }
    return
}

// Given an URL, serializes value into query string
func http_url_attach_query_string(uri string, key string, value string) string {
    u, _ := url.Parse(uri) // discarding error, don't use function with untrusted input
    v := u.Query()
    v.Add(key, value)
    u.RawQuery = v.Encode()
    return u.String()
}

// Send HTTP GET requests to specified node, logs errors and discards malformed
// responses to keep the rest of the logic clean - expects JSON response from
// Server
func http_get(host string, path string) (body []byte, err error) {
    if host == "" {
        log.Printf("http_get called with empty host")
        return []byte{}, nil
    }
    url := http_make_url(host, path)
    client := http.Client{
        Timeout: ARGV.http_timeout,
    }
    resp, err := client.Get(url) // send request
    if err != nil {
        log.Printf("Error querying %s: %s\n", url, err)
        return nil, err
    } else if dbg_http_query_verbose {
        log.Printf("HTTP response for GET %s: %v\n", url, resp)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        log.Printf("HTTP GET %s returned code %d %s: %v\n",
            url, resp.StatusCode, resp.Status, resp)
        return nil, fmt.Errorf("invalid HTTP response")
    }

    contentType := resp.Header.Get("Content-type")
    if contentType != "application/json" {
        log.Printf("HTTP GET %s did not return JSON: %v\n", url, resp)
        return nil, fmt.Errorf("JSON expected")
    }

    // read response body
    body, err = ioutil.ReadAll(resp.Body)
    if err != nil {
        log.Printf("Error reading response body for GET %s: %s\n", url, err)
        return
    } else if dbg_http_query_verbose {
        log.Printf("Body: %s\n", body)
    }
    return
}

/**** LLDP-HTTP interface *************************************************************/
// HTTP GET request wrapper for the LLDP neighbors URL. Returns the parsed JSON
// as a slice of struct Neighbor wrapped in struct NeighborLookupResult.
func http_get_node_neighbor_info(host string) (res NeighborLookupResult, err error) {
    if host == "" {
        err = fmt.Errorf("http_get_node_neighbor_info called on empty string")
        return
    }
    data, err := http_get(host, lldp_neighbor_path)

    var neighbors NeighborSlice

    if data == nil {
        err = fmt.Errorf("HTTP GET %s on '%s' failed: %w", lldp_neighbor_path, host, err)
        return
    } else {
        // parse result as JSON
        neighbors, err = parse_lldpcli_neighbors_output(host, data)
        if err != nil {
            log.Print(err)
        }

        // since this neighbor came from another topologyd, set its origin
        // because sometimes Neighbor{}s are passed around rather than
        // NeighborLookupResult{}s
        for i := range neighbors {
            neighbors[i].Origin = ORIGIN_TOPOLOGYD
        }
    }

    res = NeighborLookupResult{
        ns:     neighbors,
        origin: ORIGIN_TOPOLOGYD,  // also set its origin here on the response level
        ip:     host,
        // TODO add chassis data here
    }
    return res, err
}

// HTTP GET on the chassis URL for a given host, pull MgmtIP out of the chassis
// data which was returned
func http_get_host_mgmt_ip(host string) (ret string) {
    data, _ := http_get(host, lldp_chassis_path)
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

// Queries STP port state from host
func http_get_node_stp_port_state(host string) (ret PortToStateMap) {
    data, _ := http_get(host, stp_port_state_path)
    if data == nil { return nil }

    ret = STP_parse_port_state_json(data)
    return
}

// return text surrounded by terminal attribute for enable/disable bold font
func bold(x string) string {
    return "\033[1;1m" + x + "\033[0;0m"
}


// Send HTTP GET request to obtain STP state from neighbor, or SNMP request if
// the neighbor was obtained through SNMP
func (nr *NeighborLookupResult) gather_node_stp_state() (err error) {
    if nr.stp != nil {
        return fmt.Errorf("neighbor link state is already populated: %v", nr)
    }

    if nr.origin == ORIGIN_TOPOLOGYD {
        stp := http_get_node_stp_port_state(nr.ip)
        nr.stp = stp
    } else if ARGV.gather_snmp && nr.origin == ORIGIN_SNMP {
        stp := nr.snmp_get_node_stp_port_state()
        nr.stp = stp
    }

    return nil
}

// Map keyed by primary MgmtIP to that node's Neighbors and other info
type NodeMap map[string]NeighborLookupResult

// look up the STP state for all nodes
func (n *NodeMap) gather_stp_states() {
    for k, node := range *n {
        node.gather_node_stp_state()
        (*n)[k] = node
    }
}

// Wrapper for verbose log messages used by the neighbor gathering process
func log_gather(format string, arg... interface{}) {
    if ARGV.gather_verbose {
        log.Printf(format, arg...)
    }
}

// Send HTTP GET or SNMP requests to obtain neighbors from hosts and handle
// errors
func get_node_neighbors(ip string) (ret NeighborLookupResult) {
    ret, err := http_get_node_neighbor_info(ip)

    // XXX will make an attempt to contact the node via SNMP iff the connection
    // on the topologyd port was refused or the HTTP connection times out.
    // This is a somewhat dirty heuristic.
    if ARGV.gather_snmp &&
        (errors.Is(err, syscall.ECONNREFUSED) || os.IsTimeout(err)) {

        log.Println("No topologyd found, trying SNMP...")
        ret, err = snmp_lookup_neighbors(ip)
    }
    if err != nil {
        log.Printf("GET neighbors from '%s': error: %s. Skipping.", ip, err)
    } else if ret.ns == nil {
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
    todo := []string{ start }
    iter := 0
    ip := start

    // Get all hosts that respond to broadcast ping from the kernel's NDP table
    icmp6_ping_broadcast(ARGV.netif_link_local_ipv6)
    macToIpMap, err := ndp_get_neighbors(ARGV.netif_link_local_ipv6)
    if err != nil {log.Println(err)} // Continue anyway
    // Add all hosts found in table to the todo list
    for _, v := range macToIpMap {
        smi, err := get_suitable_mgmt_ip(v)
        if err != nil {log.Println(err); continue}
        todo = append(todo, smi)
    }

    // TODO this loop should run in parallel, see file:todo.org::*Parallelize
    //
    // loop over these nodes (in parallel goroutines) to get their LLDP
    // neighbors - either via topologyd's JSON API or if unavailable SNMP
    for len(todo) > 0 {
        ip, todo = todo[0], todo[1:]
        if v, found := neighbors[ip]; found && v.ip == ip { // check to see if it isn't empty
            log.Printf("Neighbor '%s' was already queried, skipping.", ip)
            continue
        }
        iter++
        log_gather(bold("Processing #%d (host %s), todo list: %v"), iter, ip, todo)

        nres := get_node_neighbors(ip)
        if len(nres.ns) < 1 {continue} // node reports no neighbors, skip for now... FIXME

        neighbors[ip] = nres

        for i, neigh := range nres.ns { // loop over all found neighbors
            log_gather("Neighbor (%d/%d): %+v", i+1, len(nres.ns), neigh)

            newip, err := get_suitable_mgmt_ip(neigh.MgmtIPs)
            if err != nil {
                log.Printf("gather: machine %s: failed to get management IP: %s", ip, err)
                continue
            }

            // the hashtable is dual-use to prevent duplicating lookups to
            // previously looked-up todo list entries
            if _, found := neighbors[newip]; !found {
                // initialize hashtable location to nil for deduplication
                neighbors[newip] = NeighborLookupResult{origin: 42}
                todo = append(todo, newip)
            }
        }
    }
    log_gather("== End gathering neighbors ==")

    if ARGV.query_stp_state {
        log_gather("== Begin gathering STP state ==")
        neighbors.gather_stp_states()
        log_gather("== End gathering STP state ==")
    }

    return start, &neighbors
}

// Given a primary MgmtIP address, find information about that host as seen by
// any one of its peers that knows about it
func (ns *NodeMap) mirror_mirror_on_the_wall(node string) Neighbor {
    node_neighbors := (*ns)[node]
    if len(node_neighbors.ns) == 0 {return Neighbor{}} // a hermit has no neighbors

    for _, peer := range node_neighbors.ns {
        if peer.IsEmpty() {continue} // I never introduced myself when I moved in
        peer_ip, err := get_suitable_mgmt_ip(peer.MgmtIPs)
        if err != nil {continue}
        peer_neighbors := (*ns)[peer_ip]

        mirror_image, ok := peer_neighbors.ns.find_neighbor_by_ip(node)
        if !ok || mirror_image.IsEmpty() {continue}

        return mirror_image
    }
    return Neighbor{}
}

// Given 2 neighbors, iff they're directly connected, returns the "inferior"
// PortState (i.e. smaller value of the PortState enum) of the two.
func (ns *NodeMap) stp_link_state(node string, peer string) PortState {
    // all neighbors reported by node and peer
    node_neighbors := (*ns)[node].ns
    peer_neighbors := (*ns)[peer].ns

    // find the Neighbor struct reported by each for the other
    n1, _ := node_neighbors.find_neighbor_by_ip(peer)
    n2, _ := peer_neighbors.find_neighbor_by_ip(node)

    // this synchronization errors where one peer sees the other but not in
    // return could occur if topologyd isn't running or mstpd doesn't work properly
    if n2.IsEmpty() {
        log.Printf("Warning: no reply from peer %s reported by node %s as %+v. Is mstpd/topologyd running?", peer, node, n1)
        return Unknown
    }
    if n1.IsEmpty() {
        log.Printf("Warning: no reply from node %s reported by peer %s as %+v. Is mstpd/topologyd running?", node, peer, n2)
        return Unknown
    }

    // FIXME if the same neighbor can be seen on multiple interfaces, this
    // breaks. On a ring topology, the only case is two nodes connected in a
    // ring. Evaluate under which other circumstances this can happen in other
    // topologies.
    if1 := n1.SourceIface
    if2 := n2.SourceIface

    if ps1,  ps2 := (*ns)[node].stp[if1], (*ns)[peer].stp[if2];
       ps1 < ps2 {
        return ps1
    } else {
        return ps2
    }
}

// Given two nodes, returns the name of the network interfaces on which source
// sees target
func (ns NodeMap) GetSourceIface(source string, target string) *string {
    sn := ns[source]
    if t, found := sn.ns.find_neighbor_by_ip(target); !found {
        return nil
    } else if t.SourceNeighbor != source {
        log.Printf("Huh??? Found neighbor of %s but the source neighbor isn't"+
        " identical? Please report a bug. %+v", source, t)
        return nil
    } else {
        return &t.SourceIface
    }
}

// generates graphviz output view for the graph
func generate_graphviz(start string, nodes *NodeMap) *bytes.Buffer {
    var buf bytes.Buffer

    jgf := jgf_generate_graph(start, nodes)

    buf.WriteString("strict graph {\n")

    // generate output for all individual nodes
    lines := make([]string, len(jgf.Nodes))
    for i, node := range jgf.Nodes {
        meta := jgf_node_get_metadata(&node)
        id := meta.Identifier
        if id == "" {id = "undefined"}
        var color = "black"
        if meta.Origin == ORIGIN_TOPOLOGYD {
            color = "green"
        }
        text := fmt.Sprintf("\t\"%s\" [shape=box,color=\"%s\",label=\""+
            "Hostname: %s (origin=%d)\\n"+
            "%s identifier: %s\\n"+
            "IP: %s\"]",
            //TODO escape strings
            node.Label,
            color,
            meta.Hostname, meta.Origin,
            strings.ToUpper(meta.IdType.String()), id,
            node.Label,

        )
        lines[i] = text
    }
    // sort output to make it look predictably
    sort.Strings(lines)
    // join all together and append to buffer
    buf.WriteString(strings.Join(lines, "\n"))
    buf.WriteString("\n")

    // generate output for all individual edges
    lines = make([]string, len(jgf.Edges))
    for i, edge := range jgf.Edges {
        // Add interface names to graph from Metadata
        undefined := "UNDEFINED"
        meta := jgf_edge_get_metadata(&edge)
        if meta.SourceInterface == nil { meta.SourceInterface = &undefined }
        if meta.TargetInterface == nil { meta.TargetInterface = &undefined }
        labels := fmt.Sprintf(",taillabel=\"%v\",headlabel=\"%v\"",
            *meta.SourceInterface, *meta.TargetInterface)

        // node connectivity status is displayed using different colors
        color := "cyan" // well-visible fallback if STP is disabled
        if ARGV.query_stp_state {
            rel, err := ParsePortState(edge.Relation)
            if err != nil {rel = Unknown}
            color = rel.LinkColor()
        }
        lines[i] = fmt.Sprintf("\t\"%s\" -- \"%s\" [color=\"%s\"%s]",
            edge.Source, edge.Target, color, labels)
    }
    // sort output to make it look predictably
    sort.Strings(lines)
    // join all together and append to buffer
    buf.WriteString(strings.Join(lines, "\n"))
    buf.WriteString("\n")

    buf.WriteString("}\n")

    return &buf
}

// Returns a filename suitable for opening/writing within topologyd's data
// directory
func datadir_file(filename string) string {
    return strings.Join([]string{ARGV.data_dir, filename}, "/")
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
    flag.BoolVar(     &ARGV.snmp_verbose,    "snmp-verbose",            true, "whether or not to print snmp lookups verbosely")
    flag.BoolVar(     &ARGV.gather_snmp,    "gather-snmp",              true, "whether or not to gather node neighbors via snmp if the node doesn't respond to a topologyd API request")
    flag.StringVar(   &ARGV.host_prefix,    "host-prefix",          "dc3500", "hostnames that don't start with this string generate a warning if found (set to '' to disable)")
    flag.StringVar(   &ARGV.data_dir,       "data-dir",     "/var/topologyd", "directory name where files are stored")
    flag.DurationVar( &ARGV.monitoring_freq,"monitoring-freq", 2*time.Minute, "frequency of topology change monitoring (0 disables)")
    flag.Parse()

    if len(flag.Args()) > 0 {
        log.Fatalf("Error: extra arguments on commandline: %v", flag.Args())
    }

    monitoring_init()
    snmp_init()

    // initialize http handlers
    for path, handler := range http_handlers {
        http.HandleFunc(path, handler)
    }

    if ARGV.monitoring_freq > 0 {
        ticker := time.NewTicker(ARGV.monitoring_freq)
        // start monitoring in a separate goroutine
        go (func() {
            for range ticker.C {
                monitoring_tick()
            }
        })()
    }

    // start httpd
    if err := http.ListenAndServe(fmt.Sprintf(":%d", ARGV.port), nil); err != nil {
        log.Println(err)
    }
}
