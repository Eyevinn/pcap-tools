package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/Eyevinn/pcap-tools/internal"
)

const (
	appName = "pcap-unpack"
)

var usg = `Usage of %s:

%s unpacks UDP streams from from a Wireshark/tcpdump capture.

The output is saved as files with names input_destAddress_port.ts
(assuming that the streams are MPEG-2 TS streams).
`

type options struct {
	dst     string
	version bool
}

func parseOptions(fs *flag.FlagSet, args []string) (*options, error) {
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, usg, appName, appName)
		fmt.Fprintf(os.Stderr, "\n%s [options] pcapfile [pcapfile ....]\n\noptions:\n", appName)
		fs.PrintDefaults()
	}

	opts := options{}
	fs.StringVar(&opts.dst, "dst", "", "Destination directory for output files")
	fs.BoolVar(&opts.version, "version", false, "Get mp4ff version")

	err := fs.Parse(args[1:])
	return &opts, err
}

func main() {
	if err := run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet(appName, flag.ContinueOnError)
	opts, err := parseOptions(fs, args)

	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}

	if opts.version {
		fmt.Printf("%s %s\n", appName, internal.GetVersion())
		return nil
	}

	pcapFiles := fs.Args()
	if len(pcapFiles) == 0 {
		return fmt.Errorf("no pcap files specified")
	}

	for _, pcapFile := range pcapFiles {
		err := processPCAP(pcapFile, opts.dst)
		if err != nil {
			return err
		}
	}
	return nil
}
