// This defines data structures representing JSON Graph Format as described
// here, minus hypergraphs:
// https://github.com/jsongraph/json-graph-specification
// http://jsongraphformat.info/

package jgf

import (
	"encoding/json"
)

const MIME_TYPE = "application/vnd.jgf+json"

// data structures for the subset of JGF concerning graphs (i.e. not hypergraphs)
type Node struct {
	Label      string          `json:"label,omitempty"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
}

type Edge struct {
	Source     string          `json:"source,omitempty"`
	Relation   string          `json:"relation,omitempty"`
	Target     string          `json:"target,omitempty"`
	Directed   bool            `json:"directed,omitempty"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
}

type Graph struct {
	ID        *string          `json:"id,omitempty"`
	Type       string          `json:"type,omitempty"`
	Label      string          `json:"label,omitempty"`
	Directed   bool            `json:"directed,omitempty"`
	Nodes    []Node            `json:"nodes,omitempty"`
	Edges    []Edge            `json:"edges,omitempty"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
}

type Graphs []Graph
