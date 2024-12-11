// Wrapper around newly created "topologyD" package which is required to work
// around godoc bug https://github.com/golang/go/issues/5727
// This "package" just calls the "real" main function so godoc can generate
// HTML documentation (it refuses to do so otherwise).
package main

import (
	"topologyD"
)

func main() {
	topologyD.Main()
}
