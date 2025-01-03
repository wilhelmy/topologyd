package topologyD

// This file implements monitoring of known neighbors and generates warnings if
// the network topology changes unexpectedly, i.e. does not match the defined
// "quiescent state"

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
	"sync"
)

/**** Constants - filenames and API endpoints *****************************************/

// Filenames for local data for use with datadir_file()
const (
	neighbor_db_filename = "neighbor_db.json"
	quiescent_filename   = "quiescent.json"
)

// HTTP API endpoints for monitoring.go
const (
	http_monitoring_quiescent_path = "/topology/quiescent"
	http_monitoring_status_path    = "/topology/status"
	http_monitoring_scan_path      = "/topology/scan"
)

/**** functions managing files in the data directory **********************************/

// read_neighbor_db_file() reads and unmarshals the neighbor database from disk
// as defined in the struct above.
//
// Returns «n» on success and «err» otherwise.
func read_neighbor_db_file() (n NeighborDB, err error) {
	path := datadir_file(neighbor_db_filename)
	bytes, err := ioutil.ReadFile(path)
	if os.IsNotExist(err) {return NeighborDB{}, nil}
	if err != nil {return}

	err = json.Unmarshal(bytes, &n)
	if err != nil {return}

	//n.Hashcode = "TODO" // TODO(mw) implement hashcode
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

// write_datadir_file() writes the contents of «buf» to file «fname» inside
// datadir by creating, writing and renaming a temporary file, to avoid
// truncated files. This is necessary because of all the syscalls involved, only
// rename(2) guarantees atomicity on UNIX based operating systems.
//
// Returns «err» on error.
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

// (*NeighborDB).Import() extracts all immediate neighbors of the local host
// from a network topology graph «g» and stores the result in «n».
//
// «hashcode» is currently also copied but not validated or otherwise used in
// any way.
//
// Returns «err» on error.
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

// (*NeighborDB).WriteToDisk() writes the database «n» to a file on disk
// including an updated LastModified timestamp.
//
// Returns «err» on error.
func (n *NeighborDB) WriteToDisk() (err error) {
	n.LastModified = time.Now()

	buf, err := json.Marshal(n)
	if err != nil {return}

	err = write_datadir_file(neighbor_db_filename, buf)
	if err != nil {return}

	return nil
}

// (NeighborDB).GetHashcode() returns the network hashcode for the currently
// defined quiescent topology.
func (n NeighborDB) GetHashcode() (hashcode string) {
	return n.Hashcode
}

// (NeighborDB).IsQuiescentTopologyDefined() returns true if the quiescent
// topology has been defined or successfully read from disk because the file
// exists, false otherwise.
func (n NeighborDB) IsQuiescentTopologyDefined() bool {
	// If the modification time is empty, read_neighbor_db_file() didn't return
	// an error but an empty struct, indicating a non-existing file.
	return n.LastModified != (time.Time{})
}

// (NeighborDB).CompareCurrentNeighbors compares the neighbors currently
// returned by the locally running lldpd with the neighbors that are defined as
// quiescent in the neighbor database.
//
// Since the MQTT interface for reporting the results of these monitoring cycles
// is not yet defined, it prints the results on stdout instead.
//
// Returns «err» on error.
func (n NeighborDB) CompareCurrentNeighbors() (err error) {
	current, err := get_local_neighbors()
	if err != nil {return}

	r := n.Expected.Compare(current)

	// TODO(mw) the results should be sent over a yet-to-be-defined protocol. Right
	// now, they just go to the log.
	log.Println("== Monitoring poll cycle ==")
	log.Println("quiescent:", r.Quiescent)
	log.Println("excess:   ", r.Excess)
	log.Println("missing:  ", r.Missing)
	log.Println("mismatch: ", r.Mismatching)

	return nil
}

/**** functions structure for handling the quiescent topology *************************/

// read_quiescent_topology() reads the quiescent topology previously defined for
// this network from disk.
//
// Returns the quiescent topology «g» if previously defined, an empty «g» if the
// file does not exist, or «err» on error.
func read_quiescent_topology() (g jgf.Graph, err error) {
	filename := datadir_file(quiescent_filename)
	data, err := ioutil.ReadFile(filename)
	if os.IsNotExist(err) {return g, nil} // no topology previously defined
	if err != nil {return}

	err = json.Unmarshal(data, &g)
	return
}


/**** Helper functions for validating and propagating API requests ********************/

// monitoring_jgf_valid() returns nil if the jgf input «g» is valid for
// monitoring purposes, otherwise an error.
func monitoring_jgf_valid(g jgf.Graph) (error) {
	// TODO(mw) add more validation here
	if g.Directed != false {
		return fmt.Errorf("only undirected graphs are acceptable")
	}

	return nil
}

// struct TopologyPropagationResponse is a container for reporting the
// propagation response state as well as optionally an error as JSON.
type TopologyPropagationResponse struct {
	State       string    `json:"state"`
	Error       string    `json:"error,omitempty"`
}

// monitoring_quiescent_propagate_one() propagates the new quiescent topology
// «body» to one host on API endpoint «url».
//
// Returns «status» containing the result of the propagation.
func monitoring_quiescent_propagate_one(url string, body io.ReadSeeker) (status TopologyPropagationResponse) {
	client  := http.Client{Timeout: ARGV.http_timeout}

	// body points to the end of the buffer after every request, return to
	// the beginning for the next one
	body.Seek(0, 0)

	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		log.Println("Error creating HTTP request:", err)
		return TopologyPropagationResponse{State: "error", Error: err.Error()}
	}
	req.Header.Set("Content-Type", jgf.MIME_TYPE)

	resp, err := client.Do(req)
	if err != nil {
		log.Println("propagation:", err)
		return TopologyPropagationResponse{State: "error", Error: err.Error()}
	}
	log.Printf("propagation: POST %s status=%s", url, resp.Status)

	defer resp.Body.Close()

	res, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Printf("propagation: Error reading HTTP response for %s: %v",
			resp.Request.URL.String(), err)
		return TopologyPropagationResponse{State: "error", Error: err.Error()}
	}

	if resp.StatusCode != 202 {
		errstr := fmt.Sprintf("Host returned HTTP status %s - %s",
			resp.Status, res)
		return TopologyPropagationResponse{State: "error", Error: errstr}
	}

	return TopologyPropagationResponse{State: "ok", Error: ""}
}

// monitoring_quiescent_propagate() propagates the quiescent state information
// «body» and network hashcode «hashcode» received from the network
// configuration utility to all machines contained in the topology «g» as the
// new quiescent state.
//
// Returns success status as boolean, and a map from the remote hosts' IP
// address to their TopologyPropagationResponse.
func monitoring_quiescent_propagate(g jgf.Graph, body io.ReadSeeker, hashcode string) (bool, map[string]TopologyPropagationResponse) {
	results := make(map[string]TopologyPropagationResponse, len(g.Nodes)-1)
	errors  := false

	log.Println("Propagating new topology...")

	localIPs, err := get_local_chassis_mgmt_ips()
	if err != nil {
		log.Println("Unable to get local management IP; configuration error?", err)
	}

	var wg sync.WaitGroup // used for parallelization of requests
	var results_mutex = &sync.RWMutex{}

	for _, v := range g.Nodes {
		host := v.Label
		if localIPs.Contains(host) { // skip over local machine
			log.Println("propagation: Skipping local machine", localIPs)
			continue
		}
		if host == "" { // TODO(mw) drop this as soon as it's found, not here
			log.Println("propagation: Skipping host without IP address (no topologyd/lldpd?)")
			continue
		}
		url := http_url_attach_query_string(
			http_make_url(host, http_monitoring_quiescent_path),
			"hashcode", hashcode)

		// call monitoring_quiescent_propagate_one in parallel goroutines
		wg.Add(1)
		go func(host string, url string, body io.ReadSeeker) {
			defer wg.Done()
			status := monitoring_quiescent_propagate_one(url, body)
			results_mutex.Lock()
			results[host] = status
			results_mutex.Unlock()
			if status.Error != "" {
				errors = true
			}
		}(host, url, body)
	}
	wg.Wait()

	return !errors, results
}

// hashcode_valid() validates whether the quiescent topology «data» matches the
// «hashcode».
//
// Returns true if it does and false if it does not.
func hashcode_valid(data []byte, hashcode string) bool {
	// TODO(mw) implement - a hashing algorithm for quiescent topologies hasn't
	// been invented yet.
	return len(hashcode) > 0
}

/**** REST API Handler functions ******************************************************/

// http_handle_topology_quiescent() handles HTTP POST/GET/DELETE API request for
// the quiescent topology as described in the REST API documentation.
// Parameters «w» and «req» are the usual arguments for HTTP request handlers,
// see http library documentation.
func http_handle_topology_quiescent(w http.ResponseWriter, req *http.Request) {
	// Buckle up, this is the longest function in here :)
	switch req.Method {
	case "POST":
		break // see below switch stmt
	case "GET":
		http.ServeFile(w, req, datadir_file(quiescent_filename))
		return
	case "DELETE":
		err := os.Remove(datadir_file(quiescent_filename))
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
//

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
	if err = write_datadir_file(quiescent_filename, body); err != nil {
		statuscode = http.StatusInternalServerError
		msg = "Error writing file"
		log.Println(msg, "-", err)
		http.Error(w, msg, statuscode)
		return
	}

	log.Println(bold("Topology definition succeeded!"))
	if !propagate {
		w.WriteHeader(http.StatusAccepted)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{}"))
		return
	}

	// Attempt propgagation, returning errors to client
	ok, errs := monitoring_quiescent_propagate(g, bytes.NewReader(body), hashcode)

	response, err := json.Marshal(errs)
	if err != nil {
		statuscode = http.StatusInternalServerError
		msg = "Error marshaling JSON"
		log.Println(msg)
		http.Error(w, msg, statuscode)
		return
	}

	if ok {
		log.Println("Propagation finished!")
		statuscode = http.StatusAccepted
	} else {
		log.Println("Propagation error!")
		statuscode = http.StatusFailedDependency
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statuscode)
	w.Write(response)
	return
}

// struct TopologyStatusResponse{} is the JSON response for /topology/status REST API
type TopologyStatusResponse struct {
	Hashcode      string            `json:"hashcode"`
	Quiescent   []Neighbor          `json:"quiescent"`
	Missing     []Neighbor          `json:"missing"`
	Mismatching []NeighborWithError	`json:"mismatching"`
	Excess      []Neighbor          `json:"excess"`
}

// struct Reason{} contains the mismatch reason in case an aspect of the
// real-world topology does not match what has been previously defined as
// quiescent topology.
type Reason struct {
	Key           string            `json:"key"`
	Value         string            `json:"value"`
	Expected      string            `json:"expected"`
	Message       string            `json:"message"`
}

// struct NeighborWithError{} contains all Reason{}s why this neighbor is
// registered as mismatching
type NeighborWithError struct {
	Neighbor      Neighbor          `json:"neighbor"`
	Reason      []Reason            `json:"reason"`
}

// (TopologyStatusResponse).MarshalJSON() is a JSON Marshaling wrapper to
// marshal nil slices as empty JSON array [] rather than JSON null values.
//
// Returns byte slice and error according to spec for json.Marshaler.
func (r TopologyStatusResponse) MarshalJSON() ([]byte, error) {
	type TSR TopologyStatusResponse

	a := struct {TSR}{TSR: (TSR)(r)}

	if a.Quiescent   == nil {a.Quiescent   = make([]Neighbor, 0)}
	if a.Missing     == nil {a.Missing     = make([]Neighbor, 0)}
	if a.Mismatching == nil {a.Mismatching = make([]NeighborWithError, 0)}
	if a.Excess      == nil {a.Excess      = make([]Neighbor, 0)}

	return json.Marshal(a)
}

// http_handle_topology_status() handles HTTP GET requests for the topology
// state REST API according to REST API documentation.
// Sends out TopologyStatusResponse formatted as JSON.
func http_handle_topology_status(w http.ResponseWriter, req *http.Request) {
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

// TopologyScanResponseMember is an individual member of the /topology/scan REST API endpoint.
type TopologyScanResponseMember struct {
	State          string                    `json:"state"`
	Error          string                    `json:"error,omitempty"`
	Response      *TopologyStatusResponse    `json:"response,omitempty"`
}

// TopologyScanResponse maps a host's primary MgmtIP to TopologyScanResponseMember
type TopologyScanResponse map[string]TopologyScanResponseMember

// request_topology_status() requests the topology status from remote host «ip».
//
// Returns the response «tsr» or «err» in case of an error.
func request_topology_status(ip string) (tsr TopologyStatusResponse, err error) {
	client  := http.Client{Timeout: ARGV.http_timeout}
	url := http_make_url(ip, http_monitoring_status_path)
	resp, err := client.Get(url)
	if err != nil {return}

	if resp.StatusCode != http.StatusOK {
		return tsr, fmt.Errorf("HTTP GET %s: HTTP Error %d", url, resp.StatusCode)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {return}

	err = json.Unmarshal(body, &tsr)

	return
}

// handle_topology_scan() handles the HTTP GET request for the corresponding
// REST API endpoint /topology/scan. Walks the entire network topology and
// retreives the topology status from all hosts defined.
// Parameters «w» and «req» are the usual arguments for HTTP request handlers,
// see http library documentation.
func http_handle_topology_scan(w http.ResponseWriter, req *http.Request) {
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

	var wg sync.WaitGroup
	var res_mutex = &sync.RWMutex{}

	for _, v := range g.Nodes {
		ip := v.Label

		wg.Add(1)
		go func(ip string) {
			defer wg.Done()

			r, err := request_topology_status(ip)

			res_mutex.Lock()
			if err != nil {
				log.Printf("Error requesting topology status from node (%s): %s",
					ip, err)
				res[ip] = TopologyScanResponseMember{
					State: "error",
					Error: err.Error(),
				}
			} else {
				res[ip] = TopologyScanResponseMember{
					State: "ok",
					Response: &r,
				}
			}
			res_mutex.Unlock()
		}(ip)
	}
	wg.Wait()

	buf, err := json.Marshal(res)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Println("Error marshaling json", err)
		return
	}
	w.Write(buf)
}


/**** main entry points for the monitoring system *************************************/

// monitoring_tick() is the main function of the monitoring goroutine (which
// runs in parallel to the REST API handlers at an interval defined via ARGV —
// see Main()), which verifies all expected neighbors are present in regular
// intervals and reports missing ones over a yet-to-be-defined interface.
func monitoring_tick() {
	if err := NDB.CompareCurrentNeighbors(); err != nil {
		log.Printf("Error comparing neighbors: %s", err)
	}
}

// monitoring_init() runs on topologyd start-up, registers the http handlers
// from this file in the global http handlers map and reads in the neighbor
// database.
func monitoring_init() {
    http_handlers [http_monitoring_quiescent_path] = http_handle_topology_quiescent
	http_handlers [http_monitoring_status_path   ] = http_handle_topology_status
	http_handlers [http_monitoring_scan_path     ] = http_handle_topology_scan

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
