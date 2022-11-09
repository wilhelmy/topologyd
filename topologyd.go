package main

import (
    "fmt"
    "time"
    "io/ioutil"
    "log"
    "net/http"  // Currently communicates only over a simple HTTP interface
)

const dbg_http_query_verbose = false

const port = 9090
const lldp_neighbor_path = "/lldp/neighbors"
const lldp_chassis_path  = "/lldp/chassis"

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
    // send request
    const frag = "%25br0" //%25 = %

    var url string
    if host != "localhost" {
        url = fmt.Sprintf("http://[%s%s]:%d%s", host, frag, port, path)
    } else {
        url = fmt.Sprintf("http://%s:%d%s", host, port, path)
    }
    resp, err := http.Get(url)
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

// the more wrappers, the better, right?
func get_node_neighbor_info(host string) []NeighborInterface {
    data := http_get(host, lldp_neighbor_path)
    if data == nil { return nil }

    // parse result as JSON
    ifaces, err := lldp_parse_neighbor_data(data)
    if err != nil {
        log.Print(err)
    }

    return ifaces
}

func get_localhost_mgmt_ip() string {
    const host = "localhost"
    data := http_get(host, lldp_chassis_path)
    if data == nil { return "" }

    chassisptr, err := lldp_parse_chassis_data(data)
    if err != nil {
        log.Print(err)
    }

    return (*chassisptr).LocalChassis.Chassis.Dc3500.MgmtIP
}

// Crawl the entire network for LLDP neighbors
func gather_neighbors_from_nodes() {
    // preallocate this many hashtable entries
    const prealloc = 32
    // hashmap keyed by MgmtIP addresses
    neighbors := make(map[string]*[]NeighborInterface, prealloc)

    ip   := get_localhost_mgmt_ip()
    todo := []string{ ip }

    for {
        log.Print(todo)
        var cur []NeighborInterface = get_node_neighbor_info(ip)
        if cur == nil || ip == "" {goto next} // error is logged in function call
        neighbors[ip] = &cur

        for i, _ := range cur { // loop over all found neighbors
            newip := cur[i].Chassis.Dc3500.MgmtIP

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

func main() {
    http.HandleFunc(lldp_neighbor_path, handle_lldp_request)
    http.HandleFunc(lldp_chassis_path,  handle_lldp_request)

    // start separate goroutine for httpd
    go http.ListenAndServe(fmt.Sprintf(":%d", port), nil)

    time.Sleep(1)
    gather_neighbors_from_nodes()
    for {
        time.Sleep(1)
    }
}
