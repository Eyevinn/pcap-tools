package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func processPCAP(pcapFile string, dst string) error {
	if pcapFile == "" {
		return fmt.Errorf("pcapFile is required")
	}
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return err
	}
	defer handle.Close()

	return processPcapHandle(handle, pcapFile, dst)
}

func processPcapHandle(handle *pcap.Handle, fileName, dstDir string) error {
	// Loop through packets from source
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChannel := packetSource.Packets()
	udpDsts := make(map[string]io.WriteCloser)
	for packet := range packetChannel {
		if packet == nil {
			return nil
		}
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer == nil {
			continue
		}
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip := ipLayer.(*layers.IPv4)
		udp, _ := udpLayer.(*layers.UDP)
		if udp == nil {
			continue
		}
		dstPort := int(udp.DstPort)
		dst := fmt.Sprintf("%s_%d.ts", ip.DstIP, dstPort)
		if _, ok := udpDsts[dst]; !ok {
			var dstPath string
			switch {
			case dstDir == "":
				dstPath = fmt.Sprintf("%s_%s", fileName, dst)
			default:
				base := filepath.Base(fileName)
				dstPath = filepath.Join(dstDir, fmt.Sprintf("%s_%s", base, dst))
			}
			fh, err := os.Create(dstPath)
			if err != nil {
				return err
			}
			defer fh.Close()
			fmt.Println("Created", dstPath)
			udpDsts[dst] = fh
		}
		fh := udpDsts[dst]
		_, err := fh.Write(udp.Payload)
		if err != nil {
			return err
		}
	}
	return nil
}
