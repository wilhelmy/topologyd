package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"

	"jgf" // JGF data structures
)

type IpTuple struct {
	a string
	b string
}

// Takes starting node and NodeMap, outputs JGF formatted JSON into a bytes.Buffer
func generate_jgf_graph(start string, nodes *NodeMap) (jgraph jgf.Graph) {
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

		metadata, _ := json.Marshal(nodes.mirror_mirror_on_the_wall(node_addr))
		jnodes[i] = jgf.Node{
			Label:     node_addr,
			Metadata:  metadata,
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
		for _, neighbor := range lldp_info {
			neighbor_addr, err := get_suitable_mgmt_ip(neighbor.MgmtIPs)
			if err != nil {
				log.Printf("Unable to get MgmtIP from %s: %s", neighbor_addr, err)
				continue
			}
			// found duplicate or "reverse duplicate" (i.e. the same link but
			// reported by the neighbor host)?
			if dedup[IpTuple{node_addr, neighbor_addr}] ||
			   dedup[IpTuple{neighbor_addr, node_addr}] {
				continue
			}

			link_state := nodes.stp_link_state(node_addr, neighbor_addr)
			// add jgf.Edge
 			jedges = append(jedges, jgf.Edge{
				Source:   node_addr,
				Relation: link_state.String(),
				Target:   neighbor_addr,
				Directed: false,
				Metadata: nil,
			})

			// update deduplication info
			dedup[IpTuple{node_addr, neighbor_addr}] = true
		}
	}

	// Step 3: Shove everything into a jgf.Graph
	jgraph = jgf.Graph{
		Type:     "graph",
		Label:    fmt.Sprintf("Network topology as seen from %s", start),
		Directed: false,
		Nodes:    jnodes,
		Edges:    jedges,
	}

	return
}

func generate_json_graph(start string, nodes *NodeMap) *bytes.Buffer {
	jgraph := generate_jgf_graph(start, nodes)

	// Step 4: Marshal data structure into JSON format
	b, err := json.Marshal(jgraph)
	if err != nil {
		log.Printf("Error marshaling JSON: %s\n", err)
		return nil
	}

	// Fin
	return bytes.NewBuffer(b)
}

func jgf_node_get_metadata(jnode *jgf.Node) (Neighbor) {
	var meta Neighbor
	err := json.Unmarshal((*jnode).Metadata, &meta)
	if err != nil {return Neighbor{}}
	return meta
}
