package main

import (
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"strings"
	//"regexp"
)

/*
var ping_line_regexp *regexp.Regexp

func ndp_icmp_init() {
    //64 bytes from fe80::c66e:1fff:feea:fb22%eno1: icmp_seq=1 ttl=64 time=0.535 ms
    //64 bytes from fe80::1a03:73ff:fedb:3aa8%br0: icmp_seq=1 ttl=64 time=0.710 ms (DUP!)
	ping_line_regexp = regexp.MustCompile(
		"^(?P<bytes>[0-9]+) bytes from " +
		"(?P<ipaddr>[[:alnum:]%.:]+): " +
		"icmp_seq=(?P<icmp_seq>[0-9]+) " +
		"ttl=(?P<ttl>[0-9]+) " +
		"time=(?P<time>[0-9]+\\.[0-9]+) m?s" +
	    "( \\(DUP!\\)?$") // this DUP is printed by iputils s20190709 but not 20240117
}
*/

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
		return "", fmt.Errorf(exe+" returned nonzero exit code %d", exitError.ExitCode())
	}

    return res, err
}

// broadcast ping, discards its output - only used to refresh the NDP table
func icmp6_ping_broadcast(iface string) (err error) {
	// Sends three packets for good measure in case one of them gets lost
	_, err = run_command("ping", "-c1", "ff02::1%"+iface)
	if err != nil {return}
	_, err = run_command("ping", "-c1", "ff02::1%"+iface)
	if err != nil {return}
	// This one waits for one second for the kernel to handle any responses
	_, err = run_command("ping", "-w1", "ff02::1%"+iface)
	return
}

/* This is an unfinished extended version of the above, which is supposed to
   parse the ping output. However we currently don't use that data in any way.
func icmp6_ping_bcast(iface string) (err error) {
	func icmp6_ping_bcast(iface string) (err error) {
	_, err = run_command("ping", "-w1", "ff02::1%"+iface)
	re := ping_line_regexp
	if err != nil {return}
	ress := re.FindAllStringSubmatch(out, 0)
	for x := range ress {
		log.Println(x)
	}
	for _, line := range strings.Split(out, "\n") {
		// the first line has a different format and does not match
		re.FindStringSubmatch(line)
		re.FindAllStringSubmatch(s string, n int)
	}
	return
}*/

type MacToIpsMap map[string][]string

func ndp_get_neighbors(iface string) (res MacToIpsMap, err error) {
	icmp6_ping_broadcast(iface)

	// we are actually interested in the "-br"ief output but iproute2 on the
	// machine is too old so just throw away all excess info
	out, err := run_command("ip", "neigh", "show", "dev", iface)
	if err != nil {return}

	res = make(MacToIpsMap)

	for _, line := range strings.Split(out, "\n") {
		if line == "" {break} // trailing \n before EOF
		v := strings.Split(line, " ")
		ip, mac := v[0], v[2] // the other fields we don't care about
		res[mac] = append(res[mac], ip)
	}

	return
}
