package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

/**** Commandline arguments section ***************************************************/
// Listen port for HTTP queries
var port int

// On dc3500, this is br0. For development on PC, it's the network interface connected to the DC3500 LAN.
var netif_link_local_ipv6 string

// Set to an IP address to use as a starting point. In production, this would be
// "localhost". For development, it can be any machine running topologyd.
var start_host string

// Special treatment for dc3500 hostname (other names are logged specially)
var known_relevant_chassis_name string

// Preallocate this many entries in the hashtable. Can be tuned in the future if networks are larger in practice.
var nodes_prealloc int


/**** Debug section *******************************************************************/
const dbg_http_query_verbose = false
const dbg_gather_neighbors_verbose = true

/**** Constants ***********************************************************************/
const lldp_neighbor_path = "/lldp/neighbors"
const lldp_chassis_path  = "/lldp/chassis"
const graphviz_path      = "/topology/graphviz"

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

    // TODO cache result for a few seconds?
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


// Send HTTP GET requests to specified node, logs errors and discards malformed
// responses to keep the rest of the logic clean
func http_get(host string, path string) []byte {
    if host == "" {
        log.Printf("http_get called with empty host")
        return []byte{}
    }
    var url string
    frag := ""
    if strings.ToLower(host[:5]) == "fe80:" {
        // link local IPv6 address, need to append %netif or else it isn't valid
        frag = "%25" + netif_link_local_ipv6 //%25 = %
    }
    if strings.Index(host, ":") >= 0 {
        // IPv6 address
        url = fmt.Sprintf("http://[%s%s]:%d%s", host, frag, port, path)
    } else {
        url = fmt.Sprintf("http://%s:%d%s", host, port, path)
    }
    resp, err := http.Get(url) // send request
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
func get_node_neighbor_info(host string) ([]NeighborSource, error) {
    if host == "" {
        return nil, fmt.Errorf("get_node_neighbor_info called on empty string")
    }

    data := http_get(host, lldp_neighbor_path)
    if data == nil {
        return nil, fmt.Errorf("HTTP GET %s on '%s' failed", lldp_neighbor_path, host)
    }

    // parse result as JSON
    ifaces, err := lldp_parse_neighbor_data(data)
    if err != nil {
        log.Print(err)
    }

    return ifaces, err
}

// Extracts a hopefully suitable chassis from a chassis map
func get_chassis(c ChassisMap) (ChassisMember, error) {
    if len(c) > 1 {
        return ChassisMember{},
            fmt.Errorf("This strange machine reports more than 1 chassis: %+v", c)
    }
    // centralize all this hardcoded ugliness in one spot
    if val, ok := c[known_relevant_chassis_name]; ok {
        return val, nil
    }
    // fallback: machine doesn't self-identify as known_relevant_chassis_name
    // or hostname changed; return the first chassis found and log a warning
    for k, v := range c {
        // XXX move this to an outer loop to avoid spamming the log
        log.Printf("Found machine '%s' which is seemingly not a %s: %+v", k,
            known_relevant_chassis_name, c)
        return v, nil
    }
    return ChassisMember{},
        fmt.Errorf("This strange machine reports less than 1 chassis: %+v", c)
}

// HTTP GET on the chassis URL for a given host, pull MgmtIP out of the chassis
// data which was returned
func http_get_host_mgmt_ip(host string) string {
    data := http_get(host, lldp_chassis_path)
    if data == nil { return "" }

    chassisptr, err := lldp_parse_chassis_data(data)
    if err != nil {
        log.Println(err)
        return ""
    }

    chassis, err := get_chassis((*chassisptr).LocalChassis.Chassis)
    if err != nil {
        log.Printf("machine %s: error %s", host, err)
    }

    return get_mgmt_ip(&chassis)
}

// return text surrounded by terminal attribute for enable/disable bold font
func bold(x string) string {
    return "\033[1;1m" + x + "\033[0;0m"
}

// Map keyed by primary MgmtIP to a slice of
// NeighborSources (= struct { ethernet interface, NeighborInterface })
type NodeMap map[string]*[]NeighborSource

func dbg_gather(format string, arg... interface{}) {
    if dbg_gather_neighbors_verbose {
        log.Printf(format, arg...)
    }
}

// Crawl the entire network for LLDP neighbors, returning a  slice of nodes
func gather_neighbors_from_nodes() (string, *NodeMap) {
    // hashmap keyed by MgmtIP addresses, also used for tracking whether or not
    // a node has been queried before by setting its value to nil
    neighbors := make(NodeMap, nodes_prealloc)

    dbg_gather("== Begin gathering neighbors ==")
    start:= http_get_host_mgmt_ip(start_host)
    ip   := start
    todo := []string{ ip }
    iter := 0

    for len(todo) > 0 {
        ip, todo = todo[0], todo[1:]
        iter++
        dbg_gather(bold("Processing #%d (host %s), todo list: %v"), iter, ip, todo)
        cur, err := get_node_neighbor_info(ip)
        if err != nil {
            log.Printf("GET neighbors from '%s': error: %s. Skipping.", ip, err)
            continue
        } else if cur == nil {
            log.Printf("GET neighbors from '%s': something is fishy, no object or error returned. Skipping.", ip)
            continue
        }
        neighbors[ip] = &cur

        for i, _ := range cur { // loop over all found neighbors
            dbg_gather("Neighbor (%d/%d): %+v", i+1, len(cur), cur[i].Iface.Chassis)

            chassis, err := get_chassis(cur[i].Iface.Chassis)
            if err != nil {
                log.Printf("gather: machine %s/neighbor %d: error %s", ip, i, err)
            }

            newip := get_mgmt_ip(&chassis)
            if newip == "" {
                log.Printf("gather: machine %s: failed to get management IP", ip)
                continue
            }

            if _, found := neighbors[newip]; !found {
                // initialize hashtable spot to prevent adding to todo twice
                neighbors[newip] = nil
                todo = append(todo, newip)
            }
        }
    }
    dbg_gather("== End gathering neighbors ==")

    return start, &neighbors
}

// A graph of all neighbor nodes identified by their MgmtIP (this).
// Invariant: neighbor nodes in neighbors[] should link back to this node in
// their neighbors[] member.
type NeighborGraph struct {
	this         string
	neighbors []*NeighborGraph
}

// Convenience data structure for mapping MgmtIP to the NeighborGraph starting
// from a given node.
type NeighborGraphs map[string]*NeighborGraph

func assemble_node(name string, node_neighbors *[]NeighborSource, graphs map[string]*NeighborGraph) *NeighborGraph {
    node := NeighborGraph { name, make([]*NeighborGraph, len(*node_neighbors)) }

    log.Println(graphs)
    //log.Printf("name: %s; neighbors: %+v, node_neighbors: %+v", name, neighbors, node_neighbors)

    // Loop over all neighbors found for this node, adding references to the
    // newly created struct to its neighbors but also adding references back
    // from its neighbors to this newly created node where necessary because it
    // didn't exist yet when its neighbors were allocated.
    for i, v := range *node_neighbors {
        // get neighbor's MgmtIP
        chassis, err := get_chassis(v.Iface.Chassis)
        if err != nil {
            log.Printf("Error: %s", err)
            continue
        }
        neighbor := get_mgmt_ip(&chassis)

        var seen_before bool
        node.neighbors[i], seen_before = graphs[neighbor]

        // neighbor was already initialized, link back to this node if such a ptr is missing
        if seen_before {
            // if the back reference already exists, exit early
            for _, vv := range graphs[neighbor].neighbors {
                if vv != nil && vv.this == name {goto outer_loop}
            }

            // find empty place in the slice to put the reference back to &node
            for j, vv := range graphs[neighbor].neighbors {
                if vv == nil {
                    graphs[neighbor].neighbors[j] = &node
                    goto outer_loop
                }
            }

            // XXX nothing append() couldn't fix but it shouldn't be there in the first place
            log.Printf("Warning: host %s: too many neighbors to add unexpected "+
                "reference to %s, possible bug.", neighbor, name)
        } else {
            // This node doesn't exist yet, which means it will be added later on. Skip for now.
        }
outer_loop:
    }

    return &node
}

// Takes a list of nodes generated by gather_neighbors_from_nodes and
// transforms them into a NeighborGraph, calling assemble_node on each node.
func assemble_graph(start string, neighbors *NodeMap) *NeighborGraphs {
    log.Println("assemble_graph")
    // Keep all nodes of the graph here for easy access
    graphs := make(NeighborGraphs, nodes_prealloc)
    log.Print("neighbors: ", neighbors)

    for k, v := range *neighbors {
        if v == nil {
            log.Printf("Error: neighbor '%s' has nil neighbors instead "+
                "of empty list. This is a bug.", k)
            continue
        }
        graphs[k] = assemble_node(k, v, graphs)
    }

    for k, v := range graphs {
        log.Println(k, v)
    }
    log.Println("end assemble_graph")

    return &graphs
}

func graphviz_quote_array_of_strings(strings *[]string) []byte {
    var buf bytes.Buffer

    for _, v := range *strings {
        buf.WriteString(fmt.Sprintf(" \"%s\"", v))
    }

    return buf.Bytes()
}

func generate_graphviz(start string, nodes *NodeMap) *bytes.Buffer {
    var buf bytes.Buffer

    buf.WriteString("strict graph {\n")

    for k, v := range *nodes {
        if v == nil {
            log.Printf("Error: neighbor '%s' has nil neighbors instead "+
                "of empty list. This is a bug.", k)
            continue
        }

        buf.WriteString(fmt.Sprintf("\t\"%s\" [shape=box];\n", k))
    }
    for k, v := range *nodes {
        if v == nil {continue}
        neigh := graphviz_quote_array_of_strings(get_neighbor_mgmt_ips(v))
        buf.WriteString(fmt.Sprintf("\t\"%s\" -- { %s };\n", k, neigh))
    }
    buf.WriteString("}\n")

    return &buf
}

/**** Main loop ***********************************************************************/
func main() {
    // add file name + line number to log output
    log.SetFlags(log.LstdFlags | log.Lshortfile)

    // handle command line flags
    flag.IntVar(    &port,           "port",                     9090, "listen port")
    flag.IntVar(    &nodes_prealloc, "nodes-prealloc",             32, "expected maximum number of nodes in network for memory allocation")
    flag.StringVar( &start_host,     "start-host",        "localhost", "start host for topology discovery")
    flag.StringVar( &netif_link_local_ipv6, "netif",            "br0", "network interface to use for IPv6 LL traffic")
    flag.StringVar( &known_relevant_chassis_name, "chassis", "dc3500", "hostnames other than this generate a warning if found")
    flag.Parse()

    if len(flag.Args()) > 0 {
        log.Fatalf("Error: extra arguments on commandline: %v", flag.Args())
    }

    // initialize http handlers
    http.HandleFunc(lldp_neighbor_path, handle_lldp_request)
    http.HandleFunc(lldp_chassis_path,  handle_lldp_request)

    http.HandleFunc(graphviz_path,      handle_graphviz_request)

    // start httpd
    if err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil); err != nil {
        log.Println(err)
    }
}
