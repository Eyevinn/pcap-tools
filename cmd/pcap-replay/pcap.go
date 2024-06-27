package main

import (
	"context"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"
)

func processPCAP(ctx context.Context, pcapFile string, udpHandler *udpHandler, portMap map[int]int) error {
	if pcapFile == "" {
		return fmt.Errorf("pcapFile is required")
	}
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return err
	}
	defer handle.Close()

	return processPcapHandle(ctx, handle, udpHandler, portMap)
}

func processPcapHandle(ctx context.Context, handle *pcap.Handle, udpHandler *udpHandler, portMap map[int]int) error {
	// Loop through packets from source
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChannel := packetSource.Packets()
	first := true
Loop:
	for {
		select {
		case <-ctx.Done():
			return nil
		case packet := <-packetChannel:
			if packet == nil {
				return nil
			}
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			if udpLayer == nil {
				continue Loop
			}
			timestamp := packet.Metadata().Timestamp
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
			if newPort, ok := portMap[dstPort]; ok {
				dstPort = newPort
			}
			dst := fmt.Sprintf("%s:%d", ip.DstIP, dstPort)
			udpPayload := udp.Payload
			done, err := udpHandler.AddPacket(dst, udpPayload, timestamp)
			if err != nil {
				return fmt.Errorf("add UDP packet: %w", err)
			}
			if done {
				break Loop
			}
			if first {
				log.Infof("Start time of capture: %v\n", timestamp)
				first = false
			}
			log.Debugf("From %s:%d to %s:%d length=%d\n", ip.SrcIP, udp.SrcPort, ip.DstIP, dstPort, len(udp.Payload))
		}
	}
	return nil
}
