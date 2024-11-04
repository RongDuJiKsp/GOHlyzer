package capimpl

import (
	"GOHlyzer/capture"
	"GOHlyzer/flowhd"
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
	handler, err := pcap.OpenLive(driveName, snapshotLen, promiscuous, timeout)
	if err != nil {
		return nil, err
	}
	return &OnlineCaper{handler: handler}, err
}
func (o *OnlineCaper) StartWith(h []flowhd.FlowHandler) {
	capture.HandleWith(o.handler, h)
}
