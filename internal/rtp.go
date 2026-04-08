package internal

import "encoding/binary"

// RTPHeaderLen returns the full RTP header length if payload starts with a valid
// RTP header followed by a TS sync byte (0x47). Returns 0 if not RTP.
//
// RTP header layout (RFC 3550):
//
//	 0               1
//	 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|V=2|P|X|  CC   |M|     PT      | ...
//
// Header length = 12 + CC*4 [+ 4 + extLen*4 if X is set]
func RTPHeaderLen(payload []byte) int {
	if len(payload) < 12 {
		return 0
	}
	// Version must be 2
	if payload[0]>>6 != 2 {
		return 0
	}
	cc := int(payload[0] & 0x0F)
	hdrLen := 12 + cc*4
	// Extension header
	if payload[0]&0x10 != 0 {
		extOffset := hdrLen
		if len(payload) < extOffset+4 {
			return 0
		}
		extWords := int(binary.BigEndian.Uint16(payload[extOffset+2 : extOffset+4]))
		hdrLen = extOffset + 4 + extWords*4
	}
	if len(payload) <= hdrLen {
		return 0
	}
	// Verify TS sync byte follows
	if payload[hdrLen] != 0x47 {
		return 0
	}
	return hdrLen
}
