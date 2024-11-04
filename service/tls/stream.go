package mtls

import (
	"encoding/binary"
	"github.com/open-ch/ja3"
)

type TLSStream struct {
	buf []byte
}

func ParseTLSConn(stream []byte) *TLSStream {
	return &TLSStream{stream}
}
func (s *TLSStream) Is() bool {
	return isTLSConnection(s.buf)
}
func (s *TLSStream) HandShankInfo() (*TLSRecord, error) {
	return parseTLSRecord(s.buf)
}
func (s *TLSStream) Fingerprint() string {
	j, err := ja3.ComputeJA3FromSegment(s.buf)
	if err != nil {
		return ""
	}
	return j.GetJA3Hash()
}

func isTLSConnection(data []byte) bool {
	if len(data) < 5 {
		return false
	}
	contentType := data[0]
	versionMajor := data[1]
	versionMinor := data[2]
	length := binary.BigEndian.Uint16(data[3:5])
	if contentType == 0x16 && (versionMajor == 0x03 && versionMinor <= 0x03) && len(data) >= int(5+length) {
		return true
	}
	return false
}
