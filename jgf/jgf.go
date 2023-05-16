// This defines data structures representing JSON Graph Format as described
// here, minus hypergraphs:
// https://github.com/jsongraph/json-graph-specification
// http://jsongraphformat.info/

package jgf

import (
	"encoding/json"
)

// The official MIME Type of JSON Graph Format.
const MIME_TYPE = "application/vnd.jgf+json"

/**** data structures for the subset of JGF concerning graphs (i.e. not hypergraphs) **/

// A node in the graph. In case of topologyd, a node is a computer running topologyd.
type Node struct {
	Label      string          `json:"label,omitempty"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
}

// An edge in the graph. In case of topologyd, this refers to the connection
// between machines.
type Edge struct {
	Source     string          `json:"source,omitempty"`
	Relation   string          `json:"relation,omitempty"`
	Target     string          `json:"target,omitempty"`
	Directed   bool            `json:"directed,omitempty"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
}

// The internal type for a graph object. Outside of this file, use the type
// alias Graph instead.
type _graph struct {
	ID         string          `json:"id,omitempty"`
	Type       string          `json:"type,omitempty"`
	Label      string          `json:"label,omitempty"`
	Directed   bool            `json:"directed,omitempty"`
	Nodes    []Node            `json:"nodes,omitempty"`
	Edges    []Edge            `json:"edges,omitempty"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
}

// This type alias exists to avoid infinite recursion in MarshalJSON()
type Graph _graph

// The JSON format has the graph wrapped in an additional object. Since this
// just adds clutter to the codebase if we drag it around to deal with
// elsewhere, it isn't exported, but rather automatically handled in
// MarshalJSON/UnmarshalJSON for type Graph and dealt with locally in this file.
type _graphObject struct {
	Graph    *_graph           `json:"graph"`
}

// Wrap Graph in _graphObject before marshaling JSON.
func (g Graph) MarshalJSON() (b []byte, err error) {
	var h _graphObject
	g1 := _graph(g)
	h.Graph = &g1
	return json.Marshal(h)
}

// Unwrap _graphObject wrapper when unmarshaling JSON.
func (g *Graph) UnmarshalJSON(data []byte) error {
	var h _graphObject
	if err := json.Unmarshal(data, &h); err != nil {
		return err
	}
	*g = Graph(*(h.Graph))

	return nil
}
