package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	tsPacketSize = 188
)

type udpHandler struct {
	dstAddr        string
	dstDir         string
	pktNr          int
	maxNrPackets   int
	maxNrSeconds   int
	outfiles       map[string]*os.File
	streams        map[string]bool
	conn           *net.UDPConn
	lastPayload    []byte
	startTimeStamp time.Time
	startTime      time.Time
	lastTime       time.Time // Used to detect gaps
	firstSame      int
	nrRepeatedPkts int
	gapThresholdMS int
	started        bool
}

func createUDPHandler(dstAddr string, dstDir string, gapThresholdMS int) *udpHandler {
	maxNrPackets := 1_000_000_000_000
	maxNrSeconds := 1_000_000
	uh := &udpHandler{
		dstAddr:        dstAddr,
		dstDir:         dstDir,
		maxNrPackets:   maxNrPackets,
		maxNrSeconds:   maxNrSeconds,
		streams:        make(map[string]bool),
		outfiles:       make(map[string]*os.File),
		lastPayload:    make([]byte, 7*tsPacketSize),
		started:        false,
		nrRepeatedPkts: 0,
		gapThresholdMS: gapThresholdMS,
	}
	return uh
}

func (u *udpHandler) AddPacket(dst string, udpPayload []byte, timestamp time.Time) (done bool, err error) {
	if !u.started {
		u.started = true
		u.startTimeStamp = timestamp.UTC()
		u.startTime = time.Now()
	}
	_, ok := u.streams[dst]
	if !ok {
		u.streams[dst] = true
		log.Infof("Found new UDP stream %s", dst)
		if u.dstDir != "" {
			dstFileName := strings.Replace(dst, ".", "_", -1)
			dstFileName = strings.Replace(dstFileName, ":", "_", -1) + ".ts"
			dstFilePath := path.Join(u.dstDir, dstFileName)
			err := os.MkdirAll(u.dstDir, os.ModePerm)
			if err != nil {
				return true, err
			}
			fh, err := os.Create(dstFilePath)
			if err != nil {
				return false, err
			}
			u.outfiles[dst] = fh
		}
	}
	extraBytes := len(udpPayload) % 188
	if extraBytes == 0 && bytes.Equal(udpPayload, u.lastPayload) {
		if u.firstSame == -1 {
			u.firstSame = u.pktNr
		}
		allStuffing := true
		for offset := 0; offset < len(udpPayload); offset += tsPacketSize {
			pid := (uint16(udpPayload[offset+1]&0x1f) << 8) + uint16(udpPayload[offset+2])
			if pid != 8191 {
				allStuffing = false
				break
			}
		}
		if !allStuffing {
			u.nrRepeatedPkts++
			u.pktNr++
			return
		}
	}
	u.firstSame = -1

	ok = true
	switch extraBytes {
	case 0: // One or more TS packets
		// Do nothing
	case 12: // RTP. Remove 12-byte header
		udpPayload = udpPayload[12:]
	default:
		ok = false // only count, nothing else
		if u.streams[dst] {
			log.Infof("stream %q: udp payload size %d indicates not a TS stream", dst, len(udpPayload))
			u.streams[dst] = false
		}
	}
	if u.gapThresholdMS > 0 {
		if timestamp.Sub(u.lastTime) > time.Duration(u.gapThresholdMS)*time.Millisecond && u.pktNr > 0 {
			timeDiff := timestamp.Sub(u.lastTime)
			if timeDiff > 2*time.Second {
				log.Infof("gap detected: %.3fs before packet %d", timeDiff.Seconds(), u.pktNr)
			}
		}
	}
	u.pktNr++
	u.lastTime = timestamp
	if ok {
		// Copy the full payload to lastPayload. First set the size to the same as udpPayload.
		if len(udpPayload) > int(cap(u.lastPayload)) {
			return false, fmt.Errorf("udp payload size %d is larger than capacity %d",
				len(udpPayload), cap(u.lastPayload))
		}
		u.lastPayload = u.lastPayload[:len(udpPayload)]
		copy(u.lastPayload, udpPayload)
		if u.dstDir != "" {
			_, _ = u.outfiles[dst].Write(udpPayload)
		}
		u.pktNr++
		timeDiff := timestamp.Sub(u.startTimeStamp)
		if u.pktNr%10000 == 0 {
			log.Infof("Read and sent %d packets %.3fs (%d repeated)", u.pktNr, timeDiff.Seconds(), u.nrRepeatedPkts)
		}
		if u.maxNrPackets > 0 && u.pktNr >= u.maxNrPackets {
			done = true
		}
		if u.maxNrSeconds > 0 {
			secondsPassed := int(timestamp.Sub(u.startTimeStamp).Seconds())
			if secondsPassed >= u.maxNrSeconds {
				done = true
			}
		}
		if u.dstAddr != "" {
			err := u.sendPacket(dst, udpPayload, timestamp)
			if err != nil {
				return done, err
			}
		}
	}
	return done, nil
}

func (u *udpHandler) sendPacket(dst string, udpPayload []byte, timestamp time.Time) error {
	now := time.Now()
	timeStampDiff := timestamp.Sub(u.startTimeStamp)
	timeDiff := now.Sub(u.startTime)
	diff := timeStampDiff - timeDiff
	if diff > 0 {
		time.Sleep(diff)
	}
	if u.conn == nil {
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			return fmt.Errorf("error creating UDP connection: %w", err)
		}
		u.conn = conn
	}
	port, err := strconv.Atoi(strings.Split(dst, ":")[1])
	if err != nil {
		return fmt.Errorf("error parsing port number: %w", err)
	}

	dstIP, err := toIP(u.dstAddr)
	if err != nil {
		return err
	}
	n, err := u.conn.WriteTo(udpPayload, &net.UDPAddr{IP: dstIP, Port: port})
	if err != nil {
		return fmt.Errorf("error sending UDP packet: %w", err)
	}
	if n != len(udpPayload) {
		return fmt.Errorf("sent %d bytes, expected %d", n, len(udpPayload))
	}
	return nil
}

func toIP(s string) (net.IP, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return net.IP{}, fmt.Errorf("invalid IP address: %s", s)
	}
	toByte := func(s string) byte {
		b, _ := strconv.Atoi(s)
		return byte(b)
	}
	return net.IP{toByte(parts[0]), toByte(parts[1]), toByte(parts[2]), toByte(parts[3])}, nil
}
