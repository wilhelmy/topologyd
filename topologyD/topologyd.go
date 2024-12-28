// package topologyD contains all application logic of topologyd.
package topologyD

// This is the main file of topologyd. It contains glue code, Main() logic and
// HTTP handling.

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

// Command line arguments are stored in this global struct for use everywhere in
// the program after getting parsed in Main()
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

// DEBUG: Set to true to enable verbose HTTP requests
const dbg_http_query_verbose = false

/**** Constants ***********************************************************************/

// HTTP API endpoint constants for topologyd.go
const (
    http_lldp_neighbor_path  = "/lldp/neighbors"
    http_lldp_chassis_path   = "/lldp/chassis"
    http_stp_port_state_path = "/stp/port_state"
    http_graphviz_path       = "/topology/graphviz"
    http_jgf_path            = "/topology/jgf"
)

/**** HTTP code ***********************************************************************/

// This global map contains a mapping of HTTP paths to HTTP handler functions,
// it gets filled by the various *init() functions in other subsystems and is
// then passed on to the HTTP server in Main().
var http_handlers = make(map[string]http.HandlerFunc)

// init() is called once by the go runtime at program start before main().
// It adds http handlers for topologyd.go to the aforementioned http_handlers map.
func init() {
    http_handlers [http_lldp_neighbor_path]  = http_handle_lldp
    http_handlers [http_lldp_chassis_path]   = http_handle_lldp
    http_handlers [http_stp_port_state_path] = http_handle_stp
    http_handlers [http_graphviz_path]       = http_handle_graphviz
    http_handlers [http_jgf_path]            = http_handle_jgf
}

// http_handle_lldp() handles incoming HTTP requests to query the local node's
// lldpd chassis or neighbor info from lldpd.
// Parameters «w» and «req» are the usual arguments for HTTP requests, see http
// library documentation.
//
// Returns nothing because it handles errors internally and logs them.
func http_handle_lldp(w http.ResponseWriter, req *http.Request) {
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

// http_handle_graphviz() handles incoming HTTP requests to resolve the local
// node's network neighborhood topology graph in graphviz format.
// Parameters «w» and «req» are the usual arguments for HTTP requests, see http
// library documentation.
//
// Returns nothing because it handles errors internally and logs them.
func http_handle_graphviz(w http.ResponseWriter, req *http.Request) {
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

// http_handle_jgf() handles incoming HTTP requests to resolve the network
// topology and return the result in JGF (JSON Graph Format).
// Parameters «w» and «req» are the usual arguments for HTTP requests, see http
// library documentation.
//
// Returns nothing because it handles errors internally and logs them.
func http_handle_jgf(w http.ResponseWriter, req *http.Request) {
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

// http_handle_stp() handles incoming HTTP queries to the STP API. Returns the
// local host's STP port state.
// Parameters «w» and «req» are the usual arguments for HTTP requests, see http
// library documentation.
//
// Returns nothing because it handles errors internally and logs them.
func http_handle_stp(w http.ResponseWriter, req *http.Request) {
    res := stp_get_port_state_json(ARGV.netif_link_local_ipv6)

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

// http_make_url() turns a «host» and «path» into a full URL by adding IPv6LL zone and
// port number, and wrapping IPv6 addresses in angle brackets.
//
// Returns the new «url».
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

// http_url_attach_query_string() takes an URL «uri» and adds the «key» «value»
// pair into the HTTP query string, e.g. "?key=value" with appropriate escaping.
//
// Returns the new URL as a string.
func http_url_attach_query_string(uri string, key string, value string) string {
    u, _ := url.Parse(uri) // discarding error, don't use function with untrusted input
    v := u.Query()
    v.Add(key, value)
    u.RawQuery = v.Encode()
    return u.String()
}

// http_get() sends HTTP GET requests to specified topologyd «host» API path
// «path», logs errors and discards malformed responses to keep the rest of the
// logic clean. It expects a JSON response from the remote API endpoint.
//
// Returns the response «body» as a byte slice on success and «err» on error.
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

// http_get_node_neighbor_info() fetches the LLDP neighbors from remote host
// «host» via that host's topologyd HTTP API.
//
// Returns the parsed JSON as «res» wrapped in struct NeighborLookupResult, and
// «err» in case of an error.
func http_get_node_neighbor_info(host string) (res NeighborLookupResult, err error) {
    if host == "" {
        err = fmt.Errorf("http_get_node_neighbor_info called on empty string")
        return
    }
    data, err := http_get(host, http_lldp_neighbor_path)

    var neighbors NeighborSlice

    if data == nil {
        err = fmt.Errorf("HTTP GET %s on '%s' failed: %w", http_lldp_neighbor_path, host, err)
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
        // TODO(mw) add chassis data here? This would add the need to do one
        // extra remote HTTP or SNMP lookup per remote host.  Currently
        // mirror_mirror_on_the_wall() is used instead of a separate lookup of
        // remote chassis values, which might also make the program slower due
        // to network latency.
    }
    return res, err
}

// http_get_host_mgmt_ip() sends a HTTP GET request to query the chassis data
// via the topologyd HTTP API from a given «host», extracts the MgmtIP «ret»
// out of the data which was received.
//
// Returns the remote host's MgmtIP or an empty string on error.
func http_get_host_mgmt_ip(host string) (ret string) {
    data, _ := http_get(host, http_lldp_chassis_path)
    if data == nil { return }

    chassis, err := lldp_parse_chassis_data(data)
    if err != nil {
        log.Println(err)
        return
    }

    ret, err = chassis.MgmtIPs.get_suitable_mgmt_ip()
    if err != nil {
        log.Printf("Error getting MgmtIP: %s %+v", err, chassis)
    }
    return
}

// http_get_node_stp_port_state() queries the STP port state from «host» via the
// topology HTTP API.
//
// Returns the result as a populated PortToStateMap «ret» on success,
// or nil on error.
func http_get_node_stp_port_state(host string) (ret PortToStateMap) {
    data, _ := http_get(host, http_stp_port_state_path)
    if data == nil { return nil }

    ret = stp_parse_port_state_json(data)
    return
}

// bold() formats «text» surrounded by VT102 terminal attribute for
// enable/disable bold font to print bold text on the terminal.
//
// Returns the bold text.
func bold(text string) string {
    return "\033[1;1m" + text + "\033[0;0m"
}

// (*NeighborLookupResult).gather_node_stp_state() sends a HTTP GET request to
// obtain STP state from that neighbor's topologyd API, or an SNMP request for
// that host's STP port states if the NeighborLookupResult was obtained through
// SNMP. The result is stored in the struct NeighborLookupResult on which the
// method is called.
//
// Returns «err» on error.
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

// (*NodeMap).gather_stp_states() iterates over all NeighborLookupResults in the
// map and retreives their STP port states. The result is stored back in the
// map «n».
func (n *NodeMap) gather_stp_states() {
    channels := make(map[string]chan NeighborLookupResult, len(*n))
    i := 1
    for k, node := range *n {
        channels[k] = make(chan NeighborLookupResult)
        go func(i int, node NeighborLookupResult, out chan NeighborLookupResult) {
            log_gather("Worker %d for '%s' starting", i, k)
            node.gather_node_stp_state()
            out<- node
            log_gather("Worker %d done", i)
        }(i, node, channels[k])
        i++
    }

    // read nodes from the channels and assign them back into the map
    for k, chanode := range channels {
        // it's legal to modify existing map entries while looping
        (*n)[k] = <-chanode
    }
}

// log_gather() is a wrapper function for verbose log messages used by the
// neighbor gathering process if verbose logging for the gathering process is
// enabled in ARGV. Takes a «format» string and extra «arg...» arguments for
// log.Printf().
func log_gather(format string, arg... interface{}) {
    if ARGV.gather_verbose {
        log.Printf(format, arg...)
    }
}

// get_node_neighbors() queries the LLDP neighbors from host «ip» either by
// topologyd's HTTP API or by the equivalent SNMP method if the HTTP connection
// failed because the remote host appears not to be running topologyd and SNMP
// is enabled via ARGV. Logs errors internally.
//
// Returns the resulting data «ret» or nil on error.
func get_node_neighbors(ip string) (ret NeighborLookupResult) {
    ret, err := http_get_node_neighbor_info(ip)

    // FIXME(mw) this will make an attempt to contact the node via SNMP iff the
    // connection on the topologyd port was refused or the HTTP connection times
    // out. This is a somewhat dirty heuristic, but I don't have any better idea
    // for detecting topologyd.
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

// gather_neighbors_from_nodes() crawls the entire network for LLDP neighbors
// and in succession their STP port state, starting from ARGV.start_host
// (default: localhost). It does so by creating a todo list by multicast-ping
// on the IPv6 global multicast IP to refresh the kernel's NDP table with all
// hosts responding to the ping and adding all entries from the table to the
// list. It then queries all LLDP neighbor nodes from each of the IP addresses
// in the todo list, either via the topologyd API or — if unavailable — SNMP.
// If a previously unseen host is found as a neighbor in one of the host's LLDP
// neighbors, it is added at the back of the todo list.
//
// Returns the start host as well as a Map of keyed by primary management IP to
// struct NeighborLookupResult, a container struct for the node's LLDP
// neighbors, STP port state and extra information.
func gather_neighbors_from_nodes() (string, *NodeMap) {
    // hashmap keyed by MgmtIP addresses, also used for tracking whether or not
    // a node has been queried before by setting its value to nil
    neighbors := make(NodeMap, ARGV.nodes_prealloc)

    log_gather("== Begin gathering neighbors ==")
    start:= http_get_host_mgmt_ip(ARGV.start_host)
    todo := []string{ start }
    iter := 0
    ip := start

    // Get all hosts that respond to broadcast ping from the kernel's NDP table.
    icmp6_ping_broadcast(ARGV.netif_link_local_ipv6)
    macToIpMap, err := ndp_get_neighbors(ARGV.netif_link_local_ipv6)
    if err != nil {log.Println(err)} // Continue anyway
    // Add all hosts found in table to the todo list
    for _, v := range macToIpMap {
        smi, err := MgmtIPs(v).get_suitable_mgmt_ip()
        if err != nil {log.Println(err); continue}
        todo = append(todo, smi)
    }

    // Loop over the nodes found so far in parallel goroutines to get their LLDP
    // neighbors — either via topologyd's JSON API or (if unavailable) SNMP.
    channels := make(map[string]chan NeighborLookupResult)
repeat:
    for len(todo) > 0 {
        ip, todo = todo[0], todo[1:]
        if v, found := neighbors[ip]; found && v.ip == ip { // check to see if it isn't empty
            log.Printf("Neighbor '%s' was already queried, skipping.", ip)
            continue
        }
        iter++
        log_gather(bold("Processing #%d (host %s), todo list: %v"), iter, ip, todo)

        // Make a channel for communication with the goroutine.
        channel := make(chan NeighborLookupResult)
        channels[ip] = channel
        go func(iter int, ip string){
            // FIXME(mw) this closure runs in parallel, which means that log
            // messages from log_gather/log.Println etc. will not be in order.
            // Add a log channel and rewrite all the other code to log to the
            // channel instead?
            // Set a different default logger for each goroutine?
            log_gather("Worker %d for '%s' starting", iter, ip)
            channel<- get_node_neighbors(ip)
            close(channel)
            log_gather("Worker %d done", iter)
        }(iter, ip)
    }

    // Loop over all goroutine result channels.
    // This works without using a WaitGroup because every channel produces
    // exactly one result (an empty one in case of an error). Channels block
    // until their value is read, so adding a WaitGroup proved to be more
    // trouble than just reading from all channels simultaneously.
    for ip, chanres := range channels {
        nres := <-chanres

        if len(nres.ns) < 1 {continue} // node reports no neighbors, skip for now...

        neighbors[ip] = nres

        for i, neigh := range nres.ns { // loop over all neighbors found
            log_gather("Neighbor (%d/%d): %+v", i+1, len(nres.ns), neigh)

            newip, err := neigh.MgmtIPs.get_suitable_mgmt_ip()
            if err != nil {
                log.Printf("gather: machine %s: failed to get management IP: %s", ip, err)
                continue
            }

            // the hashtable is dual-use to prevent duplicating lookups to
            // previously looked-up todo list entries
            if _, found := neighbors[newip]; !found {
                // Initialize hashtable location to an empty NLR{Origin: 42}.
                // Unique value 42 chosen for debugging, report a bug if it ever
                // shows up anywhere.
                neighbors[newip] = NeighborLookupResult{origin: 42}
                todo = append(todo, newip)
            }
        }
    }
    // if new todo items have appeared, gather again with the updated todo list.
    if len(todo) > 0 {
        log_gather("Unresolved hosts were found in remote neighbors, repeating.")
        goto repeat
    }
    log_gather("== End gathering neighbors ==")

    if ARGV.query_stp_state {
        log_gather("== Begin gathering STP state ==")
        neighbors.gather_stp_states()
        log_gather("== End gathering STP state ==")
    }

    return start, &neighbors
}

// (*NodeMap).mirror_mirror_on_the_wall() attempts to find detailed information
// about a primary MgmtIP address «node». Because the detailed information is
// never looked up directly from the node itself (via the chassis HTTP API
// endpoint or SNMP) but only ever seen through the "mirror image" as seen by
// one of its neighbors, this function iterates over all neighbors of «node» and
// attempts to look it up from that neighbor's LLDP data.
//
// Returns the node's information if found, or an empty struct otherwise.
//
// FIXME(mw) this function does not discriminate between Neighbors originating
// from a remote topologyd or SNMP switch, however the information received via
// SNMP is often less reliable depending on the network switches used, so it
// should probably prefer topologyd if both are available.
func (ns *NodeMap) mirror_mirror_on_the_wall(node string) Neighbor {
    node_neighbors := (*ns)[node]
    if len(node_neighbors.ns) == 0 {return Neighbor{}} // a hermit has no neighbors

    for _, peer := range node_neighbors.ns {
        if peer.IsEmpty() {continue} // I never introduced myself when I moved in
        peer_ip, err := peer.MgmtIPs.get_suitable_mgmt_ip()
        if err != nil {continue}
        peer_neighbors := (*ns)[peer_ip]

        mirror_image, ok := peer_neighbors.ns.find_neighbor_by_ip(node)
        if !ok || mirror_image.IsEmpty() {continue}

        return mirror_image
    }
    return Neighbor{}
}

// (*NodeMap).stp_link_state() receives two MgmtIP addresses for neighbor nodes
// «node» and «peer» as its arguments. The STP port state is based on ports, not
// links, but in order to e.g.  mark a link that has been disabled by STP in the
// graph, a "link state" has to be determined. This function calculates the
// smaller value of the two PortState enum values.
//
// Returns this "link state" if available, or logs an error and returns Unknown.
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

    // FIXME(mw) if the same neighbor can be seen on multiple interfaces, this
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

// (NodeMap).GetSourceIface() takes primary MgmtIPs of two nodes «source» and
// «target».
//
// Returns the name of the network interface on which source is connected to
// target on the source side.
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

// (NodeMap).generate_graphviz() generates a graphviz document output view for
// the graph, starting from «start» node, by iterating the «nodes» previously
// discovered.
//
// Returns a *bytes.Buffer which is suitable for a HTTP response.
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
            //TODO(mw) escape strings
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

// datadir_file() prepends topologyd's data directory to the beginning of
// «filename».
//
// Returns a path for this filename located inside topologyd's data directory.
func datadir_file(filename string) string {
    return strings.Join([]string{ARGV.data_dir, filename}, "/")
}

// Main() is the topologyd main function. It parses commandline arguments,
// initializes the SNMP and monitoring subsystems, starts the monitoring
// goroutine and the HTTP server.
func Main() {
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
