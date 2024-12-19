// This package defines data structures representing JSON Graph Format as
// described in the specification, minus hypergraphs.
//
// https://github.com/jsongraph/json-graph-specification
//
// http://jsongraphformat.info/
package jgf

import (
	"encoding/json"
)

// The official MIME Type of JSON Graph Format.
const MIME_TYPE = "application/vnd.jgf+json"

/**** data structures for the subset of JGF concerning graphs (i.e. not hypergraphs) **/

// struct Node{} represents a node in the graph. In case of topologyd, a node is
// a computer on the network. The label can be any string that uniquely
// identifies this node. Metadata can contain any extra JSON the outside world
// wants to attach to this node.
type Node struct {
	Label      string          `json:"label,omitempty"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
}

// struct Edge{} represents an edge in the graph. In case of topologyd, this
// refers to the connection between machines.
// A link between two nodes with labels "Hans" and "Jürgen" is made by
// constructing a corresponding Edge, where Relation is an optional string
// describing the relationship between these two nodes.
//
// Example:
//
//   Edge{
//     Source: "Hans",
//     Target: "Jürgen",
//     Relation: "mutual dislike",
//   }
//
// Directed is an optional flag that determines if this Edge has a direction
// from Source to Target, or if it is an undirected edge. Topologyd only uses
// undirected edges and the default is false.
//
// Metadata can be any extra JSON the package user wishes to tack onto this
// edge.
type Edge struct {
	Source     string          `json:"source,omitempty"`
	Relation   string          `json:"relation,omitempty"`
	Target     string          `json:"target,omitempty"`
	Directed   bool            `json:"directed,omitempty"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
}

// struct _graph{} is the internal type for a graph object. Outside of this
// package, use the type alias Graph instead. This type alias exists to avoid
// infinite recursion in MarshalJSON().
type _graph struct {
	ID         string          `json:"id,omitempty"`
	Type       string          `json:"type,omitempty"`
	Label      string          `json:"label,omitempty"`
	Directed   bool            `json:"directed,omitempty"`
	Nodes    []Node            `json:"nodes,omitempty"`
	Edges    []Edge            `json:"edges,omitempty"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
}

// struct Graph{} represents the graph data structure according to the JGF
// standard.
type Graph _graph

// The JSON format has the graph wrapped in an additional object. Since this
// just adds clutter to the codebase if we drag it around to deal with
// elsewhere, it isn't exported, but rather automatically handled in
// MarshalJSON/UnmarshalJSON for type Graph and dealt with locally in this
// package.
type _graphObject struct {
	Graph    *_graph           `json:"graph"`
}

// (Graph).MarshalJSON() marshals the Graph to JSON format.
//
// Returns byte slice «b» on success or «err» on error.
func (g Graph) MarshalJSON() (b []byte, err error) {
	// Wrap Graph in _graphObject before marshaling JSON.
	var h _graphObject
	g1 := _graph(g)
	h.Graph = &g1
	return json.Marshal(h)
}

// (*Graph).UnmarshalJSON() unmarshals the byte slice «data» from JSON and
// stores the result in «g».
//
// Returns «err» on error.
func (g *Graph) UnmarshalJSON(data []byte) error {
	// Unwrap _graphObject wrapper when unmarshaling JSON.
	var h _graphObject
	if err := json.Unmarshal(data, &h); err != nil {
		return err
	}
	*g = Graph(*(h.Graph))

	return nil
}
