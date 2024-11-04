package tlsextension

import (
	mtls "GOHlyzer/service/tls"
	"bytes"
	"encoding/binary"
)

const (
	SupposedVersionTLS13 uint16 = 0x0304
	SupposedVersionTLS12 uint16 = 0x0303
	SupposedVersionTLS11 uint16 = 0x0302
	SupposedVersionTLS10 uint16 = 0x0301
)

type SupposedVersionTLSExtension struct {
	BaseTLSExtension
	SupposedVersion []uint16
}

func ParseSupposedVersionExtension(raw mtls.TLSExtensionRaw) *SupposedVersionTLSExtension {
	buffer := bytes.NewBuffer(raw.Bytes)
	var serverNameListLen uint8
	_ = binary.Read(buffer, binary.BigEndian, &serverNameListLen)
	var versions []uint16
	binAvail := int(serverNameListLen)
	for binAvail >= 2 {
		var versionFlag uint16
		_ = binary.Read(buffer, binary.BigEndian, &versions)
		binAvail -= 2
		versions = append(versions, versionFlag)
	}
	return &SupposedVersionTLSExtension{BaseTLSExtension{raw.Type}, versions}
}
func ParseSupposedVersionExtensionForService(raw mtls.TLSExtensionRaw) uint16 {
	buffer := bytes.NewBuffer(raw.Bytes)
	var version uint16
	_ = binary.Read(buffer, binary.BigEndian, &version)
	return version
}
