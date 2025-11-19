package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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
		// Replace dots in IP address with underscores
		ipStr := strings.ReplaceAll(ip.DstIP.String(), ".", "_")
		dst := fmt.Sprintf("%s_%d.ts", ipStr, dstPort)
		if _, ok := udpDsts[dst]; !ok {
			var dstPath string
			// Remove file extension from input filename (e.g., .pcap)
			baseName := filepath.Base(fileName)
			baseNameWithoutExt := strings.TrimSuffix(baseName, filepath.Ext(baseName))
			switch {
			case dstDir == "":
				dstPath = fmt.Sprintf("%s_%s", baseNameWithoutExt, dst)
			default:
				dstPath = filepath.Join(dstDir, fmt.Sprintf("%s_%s", baseNameWithoutExt, dst))
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
		payload := udp.Payload
		hdrLen := len(payload) % 188

		switch hdrLen {
		case 0:
			// Pure TS, do nothing
		case 12:
			// Assume RTP header of length 12 and remove it if sync byte found
			if payload[12] == 0x47 {
				payload = payload[12:]
			}
		default:
			// Unknown header length, write anyway
		}
		_, err := fh.Write(payload)
		if err != nil {
			return err
		}
	}
	return nil
}
