package capimpl

import (
	"GOHlyzer/capture"
	"GOHlyzer/handler"
	"github.com/google/gopacket/pcap"
	"time"
)

const (
	snapshotLen int32         = 1024
	promiscuous bool          = false
	timeout     time.Duration = 30 * time.Second
)

type OnlineCaper struct {
	handler *pcap.Handle
}

func NewOnlineCaper(driveName string) (*OnlineCaper, error) {
	hd, err := pcap.OpenLive(driveName, snapshotLen, promiscuous, timeout)
	if err != nil {
		return nil, err
	}
	return &OnlineCaper{handler: hd}, err
}
func (o *OnlineCaper) StartWith(h []handler.FlowHandler) {
	capture.HandleWith(o.handler, h)
}
