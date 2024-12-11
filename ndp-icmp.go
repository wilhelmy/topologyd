package main

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"strings"
)

// run_command runs command `exe`, capturing its standard output and standard error.
// It prints stderr immediately if nonempty and returns the string from the
// command's stdout as `res` for further processing and `err` if the external
// program did not exit cleanly.
//
// FIXME this is triplicate code, see lldpcli-json.go and mstpd-status.go -- move to topologyd.go
func run_command(exe string, arg ...string) (res string, err error) {
	cmd := exec.Command(exe, arg...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	res = string(stdout.Bytes())

	if len(stderr.Bytes()) > 0 {
		log.Println(exe+" said on stderr:", stderr.String())
	}

	if exitError, ok := err.(*exec.ExitError); ok {
		return "", fmt.Errorf("%s returned nonzero exit code (%d): %w",
			exe, exitError.ExitCode(), err)
	}

    return res, err
}

// icmp_ping_host executes the system ping(8) utility on host `host` to send
// three ICMP echo requests, the last of which waits for 1 second. Output is
// discarded. Returns `err` if an error occured.
func icmp_ping_host(host string) (err error) {
	// Sends three packets for good measure in case one of them gets lost
	_, err = run_command("ping", "-c1", host)
	if err != nil {return}
	_, err = run_command("ping", "-c1", host)
	if err != nil {return}
	// This one waits for one second for the kernel to handle any responses
	_, err = run_command("ping", "-w1", host)
	return
}

// broadcast ping, discards its output - only used to refresh the NDP table
func icmp6_ping_broadcast(iface string) (err error) {
	return icmp_ping_host("ff02::1%"+iface)
}

// MacToIpsMap maps a MAC address to a list of IPs associated to that IP inside the kernel's NDP table
type MacToIpsMap map[string][]string

// ndp_get_neighbors gets the NDP neighbors by calling iproute's ip(8) command
// to query the kernel's NDP table for interface `iface`.
// Returns `err` in case of error or `res` (keyed by MAC address) in case of success.
func ndp_get_neighbors(iface string) (res MacToIpsMap, err error) {
	// we are actually interested in the "-br"ief output but iproute2 on the
	// machine is too old so just throw away all excess info
	out, err := run_command("ip", "neigh", "show", "dev", iface)
	if err != nil {return}

	res = make(MacToIpsMap)

	for _, line := range strings.Split(out, "\n") {
		if line == "" {break} // trailing \n before EOF
		v := strings.Split(line, " ")

		// in this case the MAC address is not known and the host also cannot be
		// reached so don't bother with it, skip.
		if v[len(v)-1] == "FAILED" {
			log.Printf("Warning: can't resolve MAC address of peer %s (NDP "+
				"failure). Skipping.", v[0])
			continue
		}

		ip, mac := v[0], v[2] // the other fields we don't care about
		res[mac] = append(res[mac], ip)
	}

	return
}

// IpsToMacMap map the kernel's NDP table IP addresses to their corresponding MAC address
type IpsToMacMap map[string]string

// ndp_get_mac_map gets the NDP neighbors by calling iproute's ip(8) command to
// query the kernel's NDP table for interface `iface`.
// Returns `err` in case of error or `res` (keyed by IP address) in case of success.
func ndp_get_mac_map(iface string) (res IpsToMacMap, err error) {
	// FIXME this is practically the same as ndp_get_neighbors but pivoted.
	// Instead of the code duplication, one could call the other.
	out, err := run_command("ip", "neigh", "show", "dev", iface)
	if err != nil {return}

	res = make(IpsToMacMap)

	for _, line := range strings.Split(out, "\n") {
		if line == "" {break} // trailing \n before EOF
		v := strings.Split(line, " ")

		// in this case the MAC address is not known and the host also cannot be
		// reached so don't bother with it, skip.
		if v[len(v)-1] == "FAILED" {continue}

		ip, mac := v[0], v[2] // the other fields we don't care about
		res[ip] = mac
	}

	return
}

// look up an IP address in the NDP table. Return true if the vendor of the
// corresponding MAC address is microsens.
func ndp_is_microsens(host string) bool {
	macs, _ := ndp_get_mac_map(ARGV.netif_link_local_ipv6)
	if mac, found := macs[host]; found && strings.HasPrefix(mac, "00:60:a7") {
		return true
	}
	return false
}
