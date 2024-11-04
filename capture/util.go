package capture

import (
	"GOHlyzer/handler"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func HandleWith(h *pcap.Handle, fhs []handler.FlowHandler) {
	packetSource := gopacket.NewPacketSource(h, h.LinkType())
	for packet := range packetSource.Packets() {
		for _, hd := range fhs {
			hd.NewPacket(packet)
		}
	}
	for _, hd := range fhs {
		hd.Close()
	}
	h.Close()
}
