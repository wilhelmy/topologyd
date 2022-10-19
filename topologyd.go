package main

import (
    //"fmt"
    "time"
    //"errors"
    "bytes"
    "log"
    //"strings"
    "os/exec"
    "net/http"  // Currently communicates only over a simple HTTP interface
)

func run_lldpcli_show(arg string) (*bytes.Buffer, error) {
    cmd := exec.Command("lldpcli", "-f", "json0", "show", arg)

    var out bytes.Buffer
    cmd.Stdout = &out

    if err := cmd.Run(); err != nil {
        return nil, err
    }

    return &out, nil
}

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
    if _, err := w.Write(res.Bytes()); err != nil {
        log.Printf("Request for '%s' caused failure %s\n", req.URL.Path, err)
    }
}

func main() {
    http.HandleFunc("/lldp/neighbors", handle_lldp_request)
    http.HandleFunc("/lldp/chassis",   handle_lldp_request)
    go http.ListenAndServe(":9090", nil) // start separate goroutine for httpd

    for {
        time.Sleep(1)
    }
}
