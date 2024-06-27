package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/Eyevinn/pcap-tools/internal"
)

var usg = `Usage of %s:

%s replays UDP streams from a Wireshark/tcpdump capture.

The IP address is changed to the specified value and destination ports can
be mapped to new values. One can alternatively export the streams to files.
`

type options struct {
	pcap      string
	dstAddr   string
	portMap   string
	dstDir    string
	logLevel  string
	naiveLoop bool
	version   bool
}

func parseOptions() (*options, error) {
	var opts options
	flag.StringVar(&opts.pcap, "pcap", "", "Input PCAP file")
	flag.StringVar(&opts.dstAddr, "addr", "", "Destination IP address for replayed streams")
	flag.StringVar(&opts.dstDir, "dir", "", "Destination directory for exported streams")
	flag.StringVar(&opts.portMap, "portmap", "", "Port mapping (e.g. 1234:5678,2345:6789)")
	flag.BoolVar(&opts.naiveLoop, "naiveloop", false, "Loop the PCAP file in a naive way without rewrite of packets")
	flag.StringVar(&opts.logLevel, "loglevel", "info", "Log level (info, debug, warn)")
	flag.BoolVar(&opts.version, "version", false, "Get version")

	flag.Usage = func() {
		parts := strings.Split(os.Args[0], "/")
		name := parts[len(parts)-1]
		fmt.Fprintf(os.Stderr, usg, name, name)
		fmt.Fprintf(os.Stderr, "\nRun as: %s options with options:\n\n", name)
		flag.PrintDefaults()
	}

	flag.Parse()
	return &opts, nil
}

func main() {
	ctx := context.Background()
	opts, err := parseOptions()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n\n", err)
		flag.Usage()
		os.Exit(1)
	}
	if opts.version {
		fmt.Printf("ew-pcap-replay %s\n", internal.GetVersion())
		os.Exit(0)
	}
	if opts.pcap == "" || (opts.dstAddr == "" && opts.dstDir == "") {
		fmt.Fprintf(os.Stderr, "pcap and either addr or dir must be specified")
		flag.Usage()
		os.Exit(1)
	}
	err = run(ctx, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, opts *options) error {
	hdlr := createUDPHandler(opts.dstAddr, opts.dstDir)
	nrLoops := 1
	portMap, err := parsePortMap(opts.portMap)
	if err != nil {
		return err
	}
	for {
		err := processPCAP(ctx, opts.pcap, hdlr, portMap)
		if err != nil {
			return err
		}
		if !opts.naiveLoop {
			break
		}
		log.Infof("Loop %d done", nrLoops)
		hdlr = createUDPHandler(opts.dstAddr, opts.dstDir)
		nrLoops++
	}
	return nil
}

func parsePortMap(pMap string) (map[int]int, error) {
	portMap := make(map[int]int)
	if pMap == "" {
		return portMap, nil
	}
	parts := strings.Split(pMap, ",")
	for _, p := range parts {
		pp := strings.Split(p, ":")
		if len(pp) != 2 {
			return nil, fmt.Errorf("invalid port mapping, not two parts: %s", p)
		}
		src, err := strconv.Atoi(pp[0])
		if err != nil {
			return nil, fmt.Errorf("first port map entry not a number: %s", p)
		}
		dst, err := strconv.Atoi(pp[1])
		if err != nil {
			return nil, fmt.Errorf("second port map entry not a number: %s", p)
		}
		portMap[src] = dst
	}
	return portMap, nil
}
