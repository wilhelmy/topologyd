package main

import (
    "fmt"
    "time"
    "io/ioutil"
    "log"
    "strings"
    "net/http"
)

/**** Configuration section ***********************************************************/
// XXX Most of these will be commandline flags in release, some will go away
// Listen port for HTTP queries
const port = 9090
// On dc3500, this is br0. For development on PC, it's the network interface connected to the DC3500 LAN.
const netif_link_local_ipv6 = "enp3s0"
// Set to an IP address to use as a starting point. In production, this would be "localhost"
const start_host = "fe80::6055:f4ff:fe3c:c3fc"
// Special treatment for dc3500 hostname (other names are logged specially)
const known_relevant_chassis_name = "dc3500"

/**** Debug section *******************************************************************/
const dbg_http_query_verbose = false

/**** Constants ***********************************************************************/
const lldp_neighbor_path = "/lldp/neighbors"
const lldp_chassis_path  = "/lldp/chassis"

/**** HTTP code ***********************************************************************/
// Handler function for incoming HTTP requests to query the local node's
// chassis or neighbor info
func handle_lldp_request(w http.ResponseWriter, req *http.Request) {
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

// Send HTTP GET requests to specified node, logs errors and discards malformed
// responses to keep the rest of the logic clean
func http_get(host string, path string) []byte {
    if host == "" {
        log.Printf("http_get called with empty host")
        return []byte{}
    }
    var url string
    if strings.ToLower(host[:5]) == "fe80:" {
        const frag = "%25" + netif_link_local_ipv6 //%25 = %
        url = fmt.Sprintf("http://[%s%s]:%d%s", host, frag, port, path)
    } else {
        url = fmt.Sprintf("http://%s:%d%s", host, port, path)
    }
    resp, err := http.Get(url) // send request
    if err != nil {
        log.Printf("Error querying %s: %s\n", url, err)
        return nil
    } else if dbg_http_query_verbose {
        log.Printf("HTTP response for GET %s: %s\n", url, resp)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        log.Printf("HTTP GET %s returned code %d %s: %s\n",
            url, resp.StatusCode, resp.Status, resp)
        return nil
    }

    contentType := resp.Header.Get("Content-type")
    if contentType != "application/json" {
        log.Printf("HTTP GET %s did not return JSON: %s\n", url, resp)
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
func get_node_neighbor_info(host string) []NeighborSource {
    data := http_get(host, lldp_neighbor_path)
    if data == nil { return nil }

    // parse result as JSON
    ifaces, err := lldp_parse_neighbor_data(data)
    if err != nil {
        log.Print(err)
    }

    return ifaces
}

// Extracts a hopefully suitable chassis from a chassis map
func get_chassis(c ChassisMap) (ChassisMember, error) {
    if len(c) > 1 {
        return ChassisMember{},
            fmt.Errorf("This strange machine reports more than 1 chassis: %s", c)
    }
    // centralize all this hardcoded ugliness in one spot
    if val, ok := c[known_relevant_chassis_name]; ok {
        return val, nil
    }
    // fallback: machine doesn't self-identify as DC3500 or hostname changed
    // return the first chassis found
    for k, v := range c {
        log.Printf("Found machine '%s' which is seemingly not a DC3500: %s", k, c)
        return v, nil
    }
    return ChassisMember{},
        fmt.Errorf("This strange machine reports less than 1 chassis: %s", c)
}

func get_localhost_mgmt_ip() string {
    const host = start_host
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

// Crawl the entire network for LLDP neighbors
func gather_neighbors_from_nodes() {
    // preallocate this many hashtable entries
    const prealloc = 32
    // hashmap keyed by MgmtIP addresses
    neighbors := make(map[string]*[]NeighborSource, prealloc)

    ip   := get_localhost_mgmt_ip()
    todo := []string{ ip }

    for {
        log.Print("todo", todo)
        var cur []NeighborSource = get_node_neighbor_info(ip)
        if cur == nil || ip == "" {goto next} // error is logged in function call
        neighbors[ip] = &cur

        for i, _ := range cur { // loop over all found neighbors
            chassis, err := get_chassis(cur[i].Iface.Chassis)
            if err != nil {
                log.Printf("machine %s: error %s", ip, err)
            }

            newip := get_mgmt_ip(&chassis)
            if newip == "" {continue}

            _, found := neighbors[newip]
            if !found {
                // initialize hashtable spot to prevent adding to todo twice
                neighbors[newip] = nil
                todo = append(todo, newip)
            }
        }

    next:
        if len(todo) <= 1 {
            break
        }
        ip, todo = todo[0], todo[1:]
    }

    log.Print("here")
}

/**** Main loop ***********************************************************************/
func main() {
    // add file name + line number to log output
    log.SetFlags(log.LstdFlags | log.Lshortfile)

    http.HandleFunc(lldp_neighbor_path, handle_lldp_request)
    http.HandleFunc(lldp_chassis_path,  handle_lldp_request)

    // start separate goroutine for httpd
    go http.ListenAndServe(fmt.Sprintf(":%d", port), nil)

    // XXX For development purposes
    time.Sleep(1)
    gather_neighbors_from_nodes()
    for {
        time.Sleep(1)
    }
}
