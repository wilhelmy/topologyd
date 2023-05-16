// This file bridges the gap between JGFv2 data structures from package jgf and
// structs from the main package
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

// Takes starting node and NodeMap, outputs a jgf.Graph data structure
func jgf_generate_graph(start string, nodes *NodeMap) (jgraph jgf.Graph) {
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
	// the neighbor node to the current node); since we're dealing with strict
	// graphs rather than directed graphs because ethernet connections are
	// either established or not, but there is no such case that a node can be
	// reached by its peer but not the other way around, a backlink would count
	// as a duplicate.
	var jedges []jgf.Edge
	dedup := make(map[IpTuple]bool, 2*len(*nodes))

	for node_addr, lldp_info := range *nodes {
		if lldp_info == nil { continue } // error already logged above
		for _, neighbor := range lldp_info {
			neighbor_addr, err := get_suitable_mgmt_ip(neighbor.MgmtIPs)
			if err != nil {
				log.Printf("Unable to get MgmtIP from %s: %s", neighbor_addr, err)
				continue
			}
			// found duplicate or "reverse duplicate" (i.e. the same link but
			// reported by the neighbor host)? Skip.
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
		Type:     "network topology",
		Label:    fmt.Sprintf("Network topology as seen from %s", start),
		Directed: false,
		Nodes:    jnodes,
		Edges:    jedges,
	}

	return
}

// Takes starting node and NodeMap, outputs JGF formatted JSON into a bytes.Buffer
func jgf_generate_json(start string, nodes *NodeMap) *bytes.Buffer {
	jgraph := jgf_generate_graph(start, nodes)

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


// Given a jgf.Graph and a node's primary MgmtIP, pull all MgmtIPs of immediate
// neighbor nodes from the graph
func jgf_get_neighbors_primary_mgmtips(g jgf.Graph, node string) (ips []string) {
	for _, v := range g.Edges {
		if v.Source == node {
			ips = append(ips, v.Target)
		} else if v.Target == node {
			ips = append(ips, v.Source)
		}
	}
	// TODO check if all elements in the slice are unique - duplicates shouldn't
	// happen but it can't hurt
	return
}

// Given a jgf.Graph and a node's primary MgmtIP, return all unmarshaled
// metadata neighbors from the graph.
func jgf_get_neighbors(g jgf.Graph, node string) (ns NeighborSlice, err error) {
	todo := make(map[string]bool, len(g.Nodes))
	for _, v := range jgf_get_neighbors_primary_mgmtips(g, node) {
		todo[v] = true
	}

	for k, v := range g.Nodes {
		neigh := jgf_node_get_metadata(&v)
		if neigh.IsEmpty() {
			return nil, fmt.Errorf("Neighbor %v contains no data (no lldpd?)", k)

		}
		neigh.PortState = nil
		ns = append(ns, neigh)
	}

	return
}
