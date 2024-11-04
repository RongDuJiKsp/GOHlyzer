package handler

import "github.com/google/gopacket"

type FlowHandler interface {
	NewPacket(p gopacket.Packet)
	Close()
}
