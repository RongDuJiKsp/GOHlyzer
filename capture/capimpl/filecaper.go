package capimpl

import (
	"GOHlyzer/capture"
	"GOHlyzer/handler"
	"github.com/google/gopacket/pcap"
	"os"
)

type FileCaper struct {
	handler *pcap.Handle
}

func NewFileCaper(filepath string) (*FileCaper, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	handler, err := pcap.OpenOfflineFile(file)
	if err != nil {
		return nil, err
	}
	return &FileCaper{handler: handler}, nil
}
func (f *FileCaper) StartWith(h []handler.FlowHandler) {
	capture.HandleWith(f.handler, h)
}
