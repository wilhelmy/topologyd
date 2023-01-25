package main

import (
	"fmt"
	"bytes"
	"encoding/json"
	"log"

	"jgf" // JGF data structures
)

type IpTuple struct {
	a string
	b string
}

// Takes starting node and NodeMap, outputs JGF formatted JSON into a bytes.Buffer
func generate_json_graph(start string, nodes *NodeMap) *bytes.Buffer {
	// Step 1: loop over all nodes, creating jgf.Node objects and filling the
	// list of nodes
	jnodes := make([]jgf.Node, len(*nodes))

	i := 0
	for node_addr, lldp_info := range *nodes {
        if lldp_info == nil {
            log.Printf("Error: neighbor '%s' has nil neighbors instead "+
                "of empty list. This can mean topologyd isn't running there or "+
				"it is a bug.", node_addr)
            continue
		}

		/* {{{ XXX for debugging/development until we know which metadata we need */
		md, err := json.Marshal(lldp_info)
		// TODO add relevant info from node as metadata
		_ = md;//XXX suppress go "unused variable" error
		if err != nil { md = []byte{'"', 'N', 'o', 'p', 'e', '"'} }
		/* }}} */

		jnodes[i] = jgf.Node{
			Label:     node_addr,
			Metadata:  nil /*md*/,
		}
		i += 1
	}

	// Step 2: loop over all edges, creating jgf.Edge objects and filling the
	// list of edges, while removing duplicate items (primarily backlinks from
	// the neighbor node to the current node)
	var jedges []jgf.Edge
	dedup := make(map[IpTuple]bool)

	for node_addr, lldp_info := range *nodes {
		if lldp_info == nil { continue } // error already logged above
		neighbors := get_neighbor_mgmt_ips(lldp_info)
		for _, neighbor := range *neighbors {
			// found duplicate or "reverse duplicate" (i.e. the same link but
			// reported by the neighbor host)?
			if dedup[IpTuple{node_addr, neighbor}] ||
			   dedup[IpTuple{neighbor, node_addr}] {
				continue
			}

			// add jgf.Edge
 			jedges = append(jedges, jgf.Edge{
				Source:   node_addr,
				Relation: "connected",
				Target:   neighbor,
				Directed: false,
				Metadata: nil,
			})

			// update deduplication info
			dedup[IpTuple{node_addr, neighbor}] = true
		}
	}

	// Step 3: Shove everything into a jgf.Graph
	jgraph := jgf.Graph{
		Type:     "graph",
		Label:    fmt.Sprintf("Network topology as seen from %s", start),
		Directed: false,
		Nodes:    jnodes,
		Edges:    jedges,
	}

	// Step 4: Marshal data structure into JSON format
	b, err := json.Marshal(jgraph)
	if err != nil {
		log.Printf("Error marshaling JSON: %s\n", err)
		return nil
	}

	// Fin
	return bytes.NewBuffer(b)
}
