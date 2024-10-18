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

type EdgeMetadata struct {
	SourceInterface  *string `json:"SourceInterface"`
	TargetInterface  *string `json:"TargetInterface"`
}

// Takes starting node and NodeMap, outputs a jgf.Graph data structure
func jgf_generate_graph(start string, nodes *NodeMap) (jgraph jgf.Graph) {
	// Step 1: loop over all nodes, creating jgf.Node objects and filling the
	// list of nodes
	jnodes := make([]jgf.Node, len(*nodes))

	i := 0
	for node_addr, lldp_info := range *nodes {
        if lldp_info.ns == nil {
            log.Printf("Error: neighbor '%s' has nil neighbors instead "+
                "of empty list. This can mean topologyd isn't running there or "+
				"it is a bug.", node_addr)
		}

		node_info := nodes.mirror_mirror_on_the_wall(node_addr) // TODO check if this info is better kept in NodeMap
		metadata, _ := json.Marshal(node_info)
		if node_info.IsEmpty() { metadata, _ = json.Marshal(nil) }
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
		if lldp_info.ns == nil { continue } // error already logged above
		for _, neighbor := range lldp_info.ns {
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

			metadata, _ := json.Marshal(EdgeMetadata{
				SourceInterface: nodes.GetSourceIface(node_addr, neighbor_addr),
				TargetInterface: nodes.GetSourceIface(neighbor_addr, node_addr),
				// TODO Add list of all neighbors here?
			})

			link_state := nodes.stp_link_state(node_addr, neighbor_addr)
			log.Println(node_addr, neighbor_addr, link_state)
			// add jgf.Edge
 			jedges = append(jedges, jgf.Edge{
				Source:   node_addr,
				Relation: link_state.String(),
				Target:   neighbor_addr,
				Directed: false,
				Metadata: metadata,
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

// Unmarshals the JGF node metadata back to Neighbor
func jgf_node_get_metadata(jnode *jgf.Node) (Neighbor) {
	var meta Neighbor
	err := json.Unmarshal((*jnode).Metadata, &meta)
	if err != nil {return Neighbor{}}
	return meta
}

// Unmarshals the JGF edge metadata back to EdgeMetadata
func jgf_edge_get_metadata(jedge *jgf.Edge) (EdgeMetadata) {
	var meta EdgeMetadata
	err := json.Unmarshal((*jedge).Metadata, &meta)
	if err != nil {return EdgeMetadata{}}
	return meta
}


// Given a jgf.Graph and a node's MgmtIPs, pull all MgmtIPs of immediate
// neighbor nodes from the graph
func jgf_get_neighbors_primary_mgmtips(g jgf.Graph, node_ips MgmtIPs) (ips []string) {
	for _, v := range g.Edges {
		if node_ips.Contains(v.Source) {
			ips = append(ips, v.Target)
		} else if node_ips.Contains(v.Target) {
			ips = append(ips, v.Source)
		}
	}
	// TODO check if all elements in the slice are unique - duplicates shouldn't
	// happen but it can't hurt
	return
}

// Given a jgf.Graph and a node's MgmtIPs, return all unmarshaled
// metadata neighbors for this node from the graph.
func jgf_get_neighbors(g jgf.Graph, node_ips MgmtIPs) (ns NeighborSlice, err error) {
	is_neighbor := make(map[string]bool, len(g.Nodes))
	for _, v := range jgf_get_neighbors_primary_mgmtips(g, node_ips) {
		is_neighbor[v] = true
	}

	for k, v := range g.Nodes {
		if _, found := is_neighbor[v.Label]; !found {continue} // not a neighbor

		neigh := jgf_node_get_metadata(&v)
		if neigh.IsEmpty() {
			return nil, fmt.Errorf("Neighbor %v(%s) contains no data (no topologyd?)",
				k, v.Label)
		}

		//neigh.PortState = nil
		ns = append(ns, neigh)
	}

	return
}
