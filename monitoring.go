// This file concerns itself with monitoring known neighbors and generating
// warnings if the network topology changes unexpectedly.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"jgf"
	"log"
	"net/http"
	"os"
	"time"
)

/**** Constants - filenames and API endpoints *****************************************/

const (
	_neighbor_db_file   = "neighbor_db.json"
	_quiescent_filename = "quiescent.json"
	_quiescent_api_path = "/topology/quiescent"
	_status_api_path    = "/topology/status"
)

/**** functions managing files in the data directory **********************************/

// Reads the neighbor database from disk as defined in the struct above
func read_neighbor_db_file() (n NeighborDB, err error) {
	path := datadir_file(_neighbor_db_file)
	bytes, err := ioutil.ReadFile(path)
	if os.IsNotExist(err) {return NeighborDB{}, nil}
	if err != nil {return}

	err = json.Unmarshal(bytes, &n)
	if err != nil {return}

	//n.Hashcode = "TODO"
	fi, err := os.Stat(path)
	if os.IsNotExist(err) {
		log.Println("Neighbors database was removed immediately after writing???")
		return NeighborDB{}, nil
	}
	if err != nil {
		return NeighborDB{}, err
	}
	n.LastModified = fi.ModTime()
	return
}

// Write a file by creating, writing and renaming a temporary file, to avoid
// truncated files.
func write_datadir_file(fname string, buf []byte) (err error) {
	// Atomically rename a temporary file here to avoid race conditions where
	// e.g. half of the file is written in another goroutine and garbled file
	// contents are read back in by accident.
	f, err := ioutil.TempFile(ARGV.data_dir,
		fmt.Sprintf("%s.tmp.*.pid=%d", fname, os.Getpid()))
	if err != nil {return}

	tmpfile := f.Name()
	defer os.Remove(tmpfile)

	err = ioutil.WriteFile(tmpfile, buf, 0644)
	if err != nil {return}

	err = os.Rename(tmpfile, ARGV.data_dir+"/"+fname)

	return
}

/**** struct NeighborDB receiver functions ********************************************/

// NeighborDB data structure
type NeighborDB struct {
	Hashcode		string
	LastModified	time.Time
	Expected    	NeighborSlice
}

// global singleton NDB instance
var NDB NeighborDB

// Given a jgf.Graph, take all immediate neighbors this node is supposed to have
// and add them to the NeighborDB.
func (n *NeighborDB) Import(g jgf.Graph, hashcode string) (err error) {
	n.Hashcode = hashcode

	local_ips, err := get_local_chassis_mgmt_ips()
	if err != nil {return}

	nodes, err := jgf_get_neighbors(g, local_ips)
	if err != nil {return}

	n.Expected = n.Expected[:0] // remove previous items

	// Loop over all edges, finding the neighbor belonging to that edge if it
	// touches this machine and setting the SourceIface to the correct value
	// according to the edge definition.
	for _, edge := range g.Edges {
		var peer_ip string
		iface := ""
		meta := jgf_edge_get_metadata(&edge)
		if local_ips.Contains(edge.Source) {
			peer_ip = edge.Target
			if meta.SourceInterface != nil {
				iface = *meta.SourceInterface
			}
		} else if local_ips.Contains(edge.Target) {
			peer_ip = edge.Source
			if meta.TargetInterface != nil {
				iface = *meta.TargetInterface
			}
		} else {
			continue
		}

		peer, found := nodes.find_neighbor_by_ip(peer_ip)
		if !found {continue} // this sure is someone's neighbor but not mine

		peer.SourceIface    = iface
		peer.SourceNeighbor = "LOCAL"

		n.Expected = append(n.Expected, peer)
	}

	// This field is set when writing to disk, set to zero for visibility of
	// potential bugs.
	n.LastModified = time.Time{}

	return nil
}

// Write the database file to disk including the updated LastModified timestamp
// in the struct.
func (n *NeighborDB) WriteToDisk() (err error) {
	n.LastModified = time.Now()

	buf, err := json.Marshal(n)
	if err != nil {return}

	err = write_datadir_file(_neighbor_db_file, buf)
	if err != nil {return}

	return nil
}

// Returns the network hashcode for the currently defined quiescent topology.
func (n NeighborDB) GetHashcode() (hashcode string) {
	return n.Hashcode
}

// Returns true if the quiescent topology has been defined/successfully read
// from disk because the file exists, false otherwise.
func (n NeighborDB) IsQuiescentTopologyDefined() bool {
	// If the modification time is empty, read_neighbor_db_file() didn't return
	// an error but an empty struct, indicating a non-existing file.
	return n.LastModified != (time.Time{})
}

// Compares the neighbors currently returned by the locally running lldpd with
// the neighbors that are defined as quiescent in the neighbor database.
func (n NeighborDB) CompareCurrentNeighbors() (err error) {
	current, err := get_local_neighbors()
	if err != nil {return}

	r := n.Expected.Compare(current)

	// TODO the results should be sent over a yet-to-be-defined protocol. Right
	// now, they just go to the log.
	log.Println("== Monitoring poll cycle ==")
	log.Println("quiescent:", r.Quiescent)
	log.Println("excess:   ", r.Excess)
	log.Println("missing:  ", r.Missing)
	log.Println("mismatch: ", r.Mismatching)

	return nil
}

/**** functions structure for handling the quiescent topology *************************/

// Returns the unmarshaled jgf.Graph version of the previously defined quiescent
// topology.
func read_quiescent_topology() (g jgf.Graph, err error) {
	filename := datadir_file(_quiescent_filename)
	data, err := ioutil.ReadFile(filename)
	if os.IsNotExist(err) {return g, nil} // no topology previously defined
	if err != nil {return}

	err = json.Unmarshal(data, &g)
	return
}


/**** Helper functions for validating and propagating API requests ********************/

// Returns true if the jgf input is valid for monitoring purposes, and false as
// well as a reason if it isn't
func monitoring_jgf_valid(g jgf.Graph) (error) {
	// TODO add more validation here
	if g.Directed != false {
		return fmt.Errorf("only undirected graphs are acceptable")
	}

	return nil
}

// monitoring_quiescent_propagate forwards the information received from
// DPT/configuration utility to all other machines as the new quiescent state
func monitoring_quiescent_propagate(g jgf.Graph, body io.ReadSeeker, hashcode string) (bool, map[string]string) {
	results := make(map[string]string, len(g.Nodes)-1)
	client  := http.Client{Timeout: ARGV.http_timeout}
	errors  := 0

	log.Println("Propagating new topology...")

	// TODO parallelize HTTP requests to avoid taking too long
	localIPs, err := get_local_chassis_mgmt_ips()
	if err != nil {
		log.Println("Unable to get local management IP; configuration error?", err)
	}

	for _, v := range g.Nodes {
		host := v.Label
		if localIPs.Contains(host) { // skip over local machine
			log.Println("propagation: Skipping local machine", localIPs)
			continue
		}
		if host == "" { // XXX drop this as soon as it's found, not here
			log.Println("propagation: Skipping host without IP address (no topologyd/lldpd?)")
			continue
		}

		url := http_url_attach_query_string(
			http_make_url(host, _quiescent_api_path),
			"hashcode", hashcode)

		// body points to the end of the buffer after every request, return to
		// the beginning for the next one
		body.Seek(0, 0)
		req, err := http.NewRequest("POST", url, body)
		if err != nil { // huh??
			log.Println("Error creating HTTP request:", err)
			results[host] = err.Error()
			errors++
			continue
		}
		req.Header.Set("Content-Type", jgf.MIME_TYPE)
		resp, err := client.Do(req)

		if err != nil {
			results[host] = err.Error()
			log.Println("propagation:", err)
			errors++
			continue
		}
		log.Printf("propagation: POST %s status=%s", url, resp.Status)

		defer resp.Body.Close()

		res, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Printf("propagation: Error reading HTTP response for %s: %v",
				resp.Request.URL.String(), err)
			results[host] = err.Error()
			errors++
			continue
		}

		if resp.StatusCode != 202 {
			results[host] = fmt.Sprintf("Host returned HTTP status %s - %s",
				resp.Status, res)
			errors++
		} else {
			// set to nil if no error, so the client can identify all hosts that
			// accepted the topology change
			results[host] = "OK"
		}
	}
	return errors == 0, results
}

// Given a definition of a quiescent topology, determine whether or not it
// matches the hashcode
func hashcode_valid(data []byte, hashcode string) bool {
	// TODO implement
	return len(hashcode) > 0
}

/**** REST API Handler functions ******************************************************/

// handle POST/GET/DELETE request for the "normal" topology state.
func handle_topology_quiescent(w http.ResponseWriter, req *http.Request) {
	// Buckle up, this is the longest function in here :)
	switch req.Method {
	case "POST":
		break // see below switch stmt
	case "GET":
		http.ServeFile(w, req, datadir_file(_quiescent_filename))
		return
	case "DELETE":
		err := os.Remove(datadir_file(_quiescent_filename))
		if err != nil {
			log.Println("Error deleting quiescent topology:", err)
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			log.Println("Quiescent topology deleted")
			w.WriteHeader(http.StatusNoContent)
		}
		return
	default:
        w.WriteHeader(http.StatusMethodNotAllowed)
        log.Printf("Request for '%s': HTTP method %s not suppported",
			req.URL.Path, req.Method)
		return
	}

	// POST request handler
	var statuscode   int        // HTTP Status code
	var msg          string     // HTTP Message sent along with the status code

	// Is this request a propagation request? (?propagate=true in query string)
	propagate := req.URL.Query().Get("propagate") == "true"
	// Network hashcode (must be set when defining a topology)
	hashcode  := req.URL.Query().Get("hashcode")

	var g            jgf.Graph  // the graph passed into the POST request
	var body       []byte       // request body
	var err          error      // error (if any)

	log.Printf("HTTP POST %s, topology (re)definition request", req.URL)

	// validate MIME type
	if req.Header.Get("Content-Type") != jgf.MIME_TYPE {
		msg = fmt.Sprintf("Content-Type header is %s (should be %s)",
			req.Header.Get("Content-Type"), jgf.MIME_TYPE)
		statuscode = http.StatusUnsupportedMediaType
		log.Println(msg)
		http.Error(w, msg, statuscode)
		return
	}

	// read request body
	if body, err = ioutil.ReadAll(req.Body); err != nil {
		msg = "Error reading HTTP request body"
		statuscode = http.StatusBadRequest
		log.Println(msg, "-", err)
		http.Error(w, msg, statuscode)
		return
	}

	// unmarshal request body into jgf.Graph
	if err = json.Unmarshal(body, &g); err != nil {
		msg = "Error unmarshaling JSON"
		statuscode = http.StatusBadRequest
		log.Println(msg, "-", err, body)
		http.Error(w, msg, statuscode)
		return
	}

	// validate JGF integrity
	if err = monitoring_jgf_valid(g); err != nil {
		msg = "Invalid JGF formatted data"
		statuscode = http.StatusBadRequest
		log.Println(msg, "-", err)
		http.Error(w, msg, statuscode)
		return
	}

	// validate network hashcode
	if !hashcode_valid(body, hashcode) {
		statuscode = http.StatusBadRequest
		msg = "hashcode invalid"
		log.Println(msg)
		http.Error(w, msg, statuscode)
		return
	}

	// Create a backup copy of the previously defined neighbor db in case
	// something goes wrong while writing to disk
	ndb_backup := NDB

	// Import immediate neighbors into neighbor DB
	if err = NDB.Import(g, hashcode); err != nil {
		statuscode = http.StatusInternalServerError
		msg = "Error importing new topology"
		log.Println(msg, "-", err)
		http.Error(w, msg, statuscode)
		// last resort, restore previous neighbor db
		NDB = ndb_backup
		return
	}

	// Write the database file to disk
	if err = NDB.WriteToDisk(); err != nil {
		statuscode = http.StatusInternalServerError
		msg = "Error writing file"
		log.Println(msg, "-", err)
		http.Error(w, msg, statuscode)
		// last resort, restore previous neighbor db
		NDB = ndb_backup
		// this probably doesn't work but leaves the system in a slightly less
		// inconsistent state
		log.Printf("Writing previous neighbor DB back to disk: %s",
			NDB.WriteToDisk())
		return
	}

	// Write quiescent topology to disk (it has its own file, which contains the
	// unmodified POST data from this request)
	if err = write_datadir_file(_quiescent_filename, body); err != nil {
		statuscode = http.StatusInternalServerError
		msg = "Error writing file"
		log.Println(msg, "-", err)
		http.Error(w, msg, statuscode)
		return
	}

	log.Println(bold("Topology definition succeeded!"))
	if !propagate {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// Attempt propgagation, returning errors to client
	ok, errs := monitoring_quiescent_propagate(g, bytes.NewReader(body), hashcode)
	var response []byte
	if !ok {
		response, err = json.Marshal(errs)
		if err != nil {
			statuscode = http.StatusInternalServerError
			msg = "Error marshaling JSON"
			log.Println(msg)
			http.Error(w, msg, statuscode)
			return
		}
		statuscode = http.StatusFailedDependency
		msg = "Propagation error"
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statuscode)
		w.Write(response)
		return
	}
	log.Println("Propagation finished!")
	w.WriteHeader(http.StatusAccepted)
}

// The response JSON for /topology/status
type TopologyStatusResponse struct {
	Hashcode      string            `json:"hashcode"`
	Quiescent   []Neighbor          `json:"quiescent"`
	Missing     []Neighbor          `json:"missing"`
	Mismatching []NeighborWithError	`json:"mismatching"`
	Excess      []Neighbor          `json:"excess"`
}

// Mismatch reason
type Reason struct {
	Key           string            `json:"key"`
	Value         string            `json:"value"`
	Expected      string            `json:"expected"`
	Message       string            `json:"message"`
}

// Mismatching neighbors with all mismatch reasons
type NeighborWithError struct {
	Neighbor      Neighbor          `json:"neighbor"`
	Reason      []Reason            `json:"reason"`
}

// Marshal nil slices as empty JSON array rather than null
func (r TopologyStatusResponse) MarshalJSON() ([]byte, error) {
	type TSR TopologyStatusResponse

	a := struct {TSR}{TSR: (TSR)(r)}

	if a.Quiescent   == nil {a.Quiescent   = make([]Neighbor, 0)}
	if a.Missing     == nil {a.Missing     = make([]Neighbor, 0)}
	if a.Mismatching == nil {a.Mismatching = make([]NeighborWithError, 0)}
	if a.Excess      == nil {a.Excess      = make([]Neighbor, 0)}

	return json.Marshal(a)
}

// handle GET request for the topology state. Returns 3 sets of nodes: quiescent
// nodes, excess nodes and missing nodes.
func handle_topology_status(w http.ResponseWriter, req *http.Request) {
    log.Printf("Received HTTP %s from %s for %s",
		req.Method, req.RemoteAddr, req.URL.Path)

	if req.Method != "GET" {
        w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	n, err := read_neighbor_db_file()
	if err != nil {
		log.Println("  HTTP Response 500: Error reading neighbor database:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// If the quiescent topology was never defined, there is no status.
	if !n.IsQuiescentTopologyDefined() {
		log.Println("  HTTP Response 503: quiescent topology not defined")
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	current, err := get_local_neighbors()
	if err != nil {return}

	r := n.Expected.Compare(current)
	r.Hashcode = n.GetHashcode()

	response, err := json.Marshal(r)
	if err != nil {
		log.Printf("Error marshaling JSON: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}

// Maps primary MgmtIP to TopologyScanResponse
type TopologyScanResponse map[string]*TopologyStatusResponse

func request_topology_status(ip string) (tsr TopologyStatusResponse, err error) {
	url := http_make_url(ip, _status_api_path)
	resp, err := http.Get(url)
	if err != nil {return}

	if resp.StatusCode != http.StatusOK {
		return tsr, fmt.Errorf("HTTP GET %s: HTTP Error %d", url, resp.StatusCode)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {return}

	err = json.Unmarshal(body, &tsr)

	return
}

// handle_topology_scan handles the GET request for the corresponding API
// endpoint /topology/scan. Walks the entire topology and retreives the topology
// status from all nodes.
func handle_topology_scan(w http.ResponseWriter, req *http.Request) {
    log.Printf("Received HTTP %s from %s for %s",
		req.Method, req.RemoteAddr, req.URL.Path)

	if req.Method != "GET" {
        w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	g, err := read_quiescent_topology()
	if err != nil {
		log.Println("  HTTP Response 500: Error reading neighbor database:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	res := make(TopologyScanResponse, len(g.Nodes))
	for _, v := range g.Nodes {
		ip := v.Label
		r, err := request_topology_status(ip)
		if err != nil {
			log.Println(err)
			/* TODO not specified in API response document */
			res[ip] = nil // "Failed to request topology status from host"
			continue
		}
		res[ip] = &r
	}

	buf, err := json.Marshal(res)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Println("Error marshaling json", err)
		return
	}
	w.Write(buf)
}


/**** main entry points for the monitoring system *************************************/

// main function of the monitoring goroutine (which runs in parallel to the REST
// API handlers at an interval defined via ARGV - see main()), which verifies
// all expected neighbors are present in regular intervals and reports missing
// ones over a yet-to-be-defined interface (TODO).
func monitoring_tick() {
	if err := NDB.CompareCurrentNeighbors(); err != nil {
		log.Printf("Error comparing neighbors: %s", err)
	}
}

// monitoring_init registers http handlers in the global http handlers map and
// reads in the neighbor database
func monitoring_init() {
    http_handlers [_quiescent_api_path] = handle_topology_quiescent
	http_handlers [_status_api_path] = handle_topology_status
	http_handlers ["/topology/scan"] = handle_topology_scan

	var err error
	NDB, err = read_neighbor_db_file()
	if err != nil {
		log.Printf("Error reading neighbor database: %s - potential bug?", err)
	} else if !NDB.IsQuiescentTopologyDefined() {
		log.Printf("Neighbor database has not been defined")
	} else {
		log.Println("Found neighbor database, last update:", NDB.LastModified)
	}
}
