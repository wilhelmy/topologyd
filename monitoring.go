// This file concerns itself with monitoring known neighbors and generating
// warnings if the network topology changes unExpectedly.

package main

import (
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
	_neighbor_db_file = "neighbor_db.json"
	_quiescent_filename = "quiescent.json"
	_quiescent_api_path = "/topology/quiescent"
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
	f, err := os.CreateTemp(ARGV.data_dir, fname+"*.tmp")
	if err != nil {return}
	tmpfile := f.Name()

	_, err = f.Write(buf)
	if err != nil {return}

	err = f.Close()
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

	ip, err := get_local_chassis_mgmt_ip()
	if err != nil {return}

	nei, err := jgf_get_neighbors(g, ip)
	if err != nil {return}

	n.Expected = nei

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

	/* TODO reuse code from scan API endpoint */
	quiescent, excess, missing := n.Expected.Compare(current)

	log.Println("quiescent:", quiescent)
	log.Println("excess:   ", excess)
	log.Println("missing:  ", missing)

	return nil
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
func monitoring_quiescent_propagate(g jgf.Graph, body io.Reader) (bool, map[string]error) {
	results := make(map[string]error, len(g.Nodes)-1)
	client  := http.Client{Timeout: ARGV.http_timeout}
	errors  := 0

	// TODO parallelize HTTP requests to avoid taking too long
	localIP, err := get_local_chassis_mgmt_ip()
	if err != nil {
		log.Println("Unable to get local management IP; configuration error?", err)
	}
	for _, v := range g.Nodes {
		host := v.Label
		if host == localIP {continue} // skip over local machine
		if host == "" { // XXX drop this as soon as it's found, not here
			log.Println("Host without IP address (no topologyd/lldpd?). Skipping")
			continue
		}
		url := http_make_url(host, _quiescent_api_path)
		resp, err := client.Post(url, jgf.MIME_TYPE, body)
		if err != nil {
			results[host] = err
			log.Println(err)
			errors++
			continue
		}
		if resp.StatusCode < 200 && resp.StatusCode >= 300 {
			results[host] = fmt.Errorf("host returned HTTP status %d %s - %s",
				resp.StatusCode, resp.Status, resp.Body)
			errors++
		} else {
			// set to nil if no error, so the client can identify all hosts that
			// accepted the topology change
			results[host] = nil
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
		log.Println(msg, "-", err)
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
	ok, errs := monitoring_quiescent_propagate(g, req.Body)
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
	}
	statuscode = http.StatusFailedDependency
	msg = "Propagation error"
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statuscode)
	w.Write(response)
}

type NeighborWithError struct {
	Neighbor      Neighbor          `json:"neighbor"`
	Reason        string            `json:"reason"`
}
type TopologyStatusResponse struct {
	Hashcode      string            `json:"hashcode"`
	Quiescent   []Neighbor          `json:"quiescent"`
	Missing     []Neighbor          `json:"missing"`
	Mismatching []NeighborWithError	`json:"mismatching"`
	Excess      []Neighbor          `json:"excess"`
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
		log.Println("  HTTP Response 404: quiescent topology not defined")
        w.WriteHeader(http.StatusNotFound)
		return
	}

	current, err := get_local_neighbors()
	if err != nil {return}

	var r TopologyStatusResponse
	var mismatch []Neighbor
	r.Hashcode = n.GetHashcode()
	r.Quiescent, r.Excess, mismatch = n.Expected.Compare(current)

	// TODO XXX this should have the actual mismatch information from Compare()
	for _, v := range mismatch {
		r.Mismatching = append(r.Mismatching,
			NeighborWithError{v, "Neighbor does not match configuration!"})
	}

	response, err := json.Marshal(r)
	if err != nil {
		log.Printf("Error marshaling JSON: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(response)
}


/**** main entry points for the monitoring system *************************************/

// main function of the monitoring goroutine (which runs in parallel to the REST
// API handlers at an interval defined via ARGV - see main()), which verifies
// all expected neighbors are present in regular intervals and reports missing
// ones over a yet-to-be-defined interface.
func monitoring_tick() {
	if err := NDB.CompareCurrentNeighbors(); err != nil {
		log.Printf("Error comparing neighbors: %s", err)
	}
}

// monitoring_init registers http handlers in the global http handlers map and
// reads in the neighbor database
func monitoring_init() {
    http_handlers [_quiescent_api_path] = handle_topology_quiescent
	http_handlers ["/topology/status"] = handle_topology_status
	//http_handlers ["/topology/scan"] // TODO

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
