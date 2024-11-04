package tlsextension

import (
	mtls "GOHlyzer/service/tls"
	"bytes"
	"encoding/binary"
)

const (
	ServerNameHostName uint8 = 0x00
)

type ServerNameTLSExtension struct {
	BaseTLSExtension
	ServiceNames []ServiceName
}

type ServiceName struct {
	NameType uint8
	Name     []byte
}

func ParseServerNameExtension(raw mtls.TLSExtensionRaw) *ServerNameTLSExtension {
	buffer := bytes.NewBuffer(raw.Bytes)
	var serverNameListLen uint16
	_ = binary.Read(buffer, binary.BigEndian, &serverNameListLen)
	var serviceNames []ServiceName
	binAvail := int(serverNameListLen)
	for binAvail >= 3 {
		var nameType uint8
		var nameLen uint16

		_ = binary.Read(buffer, binary.BigEndian, &nameType)
		_ = binary.Read(buffer, binary.BigEndian, &nameLen)
		name := buffer.Next(int(nameLen))
		serviceNames = append(serviceNames, ServiceName{nameType, name})
		binAvail -= 3 + int(nameLen)
	}
	return &ServerNameTLSExtension{BaseTLSExtension{raw.Type}, serviceNames}
}
