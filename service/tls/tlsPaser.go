package mtls

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	RecordTypeTLSHandShank   uint8 = 0x16
	HandshakeTypeClientHello uint8 = 1
	HandshakeTypeServerHello uint8 = 2
)

type TLSRecord struct {
	RecordType      uint8
	Version         uint16
	Length          uint16
	HandshakeRecord *TLSHandshakeRecord
}

func parseTLSRecord(data []byte) (*TLSRecord, error) {
	var recordType uint8
	var version uint16
	var length uint16
	buffer := bytes.NewBuffer(data)
	if err := binary.Read(buffer, binary.BigEndian, &recordType); err != nil {
		return nil, err
	}
	if err := binary.Read(buffer, binary.BigEndian, &version); err != nil {
		return nil, err
	}
	if err := binary.Read(buffer, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	if recordType != RecordTypeTLSHandShank {
		return &TLSRecord{recordType, version, length, nil}, nil
	}
	handshakeData := buffer.Next(int(length))
	handshake, err := parseHandshake(handshakeData)
	if err != nil {
		return nil, err
	}
	return &TLSRecord{recordType, version, length, handshake}, nil
}

type TLSHandshakeRecord struct {
	HandshakeType uint8
	Length        uint32
	ClientHello   *TLSClientHelloMsg
	ServiceHello  *TLSServerHelloMsg
}

func parseHandshake(data []byte) (*TLSHandshakeRecord, error) {
	var handshakeType uint8
	var length [3]byte

	// 读取握手消息类型和长度
	buffer := bytes.NewBuffer(data)
	handshakeType, _ = buffer.ReadByte()
	length = [3]byte(buffer.Next(3))
	handshakeLength := uint32(length[0])<<16 | uint32(length[1])<<8 | uint32(length[2]) //大端序

	// 解析具体的握手消息（这里只处理ClientHello和ServerHello）
	switch handshakeType {
	case HandshakeTypeClientHello:
		hello, err := parseClientHello(buffer.Next(int(handshakeLength)))
		if err != nil {
			return nil, err
		}
		return &TLSHandshakeRecord{handshakeType, handshakeLength, hello, nil}, nil
	case HandshakeTypeServerHello:
		hello, err := parseServiceHello(buffer.Next(int(handshakeLength)))
		if err != nil {
			return nil, err
		}
		return &TLSHandshakeRecord{handshakeType, handshakeLength, nil, hello}, nil
	default:
		return nil, errors.New(fmt.Sprintf("Other Handshake Type: %d\n", handshakeType))
	}
}

type TLSHelloMsg struct {
	Version     uint16
	RandomBytes [32]byte
	SessionID   []byte
	Extensions  []TLSExtensionRaw
}
type TLSClientHelloMsg struct {
	*TLSHelloMsg
	CipherSuites      []uint16
	CompressionMethod []byte
}

func parseClientHello(data []byte) (*TLSClientHelloMsg, error) {
	buffer := bytes.NewBuffer(data)
	var version uint16
	if err := binary.Read(buffer, binary.BigEndian, &version); err != nil {
		return nil, err
	}
	randomByte := [32]byte(buffer.Next(32))
	sessionIDLength, _ := buffer.ReadByte()
	sessionID := buffer.Next(int(sessionIDLength))
	var cipherSuiteLength uint16
	if err := binary.Read(buffer, binary.BigEndian, &cipherSuiteLength); err != nil {
		return nil, err
	}
	var cipherSuites []uint16
	for range cipherSuiteLength / 2 {
		var cipherSuite uint16
		if err := binary.Read(buffer, binary.BigEndian, &cipherSuite); err != nil {
			return nil, err
		}
		cipherSuites = append(cipherSuites, cipherSuite)
	}
	compressionMethodsLen, _ := buffer.ReadByte()
	compressionMethod := buffer.Next(int(compressionMethodsLen))
	var extensionsLength uint16

	if err := binary.Read(buffer, binary.BigEndian, &extensionsLength); err != nil {
		return nil, err
	}
	extensions, err := ParseBasicExtensions(buffer.Next(int(extensionsLength)))
	if err != nil {
		return nil, err
	}
	return &TLSClientHelloMsg{
		&TLSHelloMsg{version, randomByte, sessionID, extensions},
		cipherSuites, compressionMethod,
	}, nil
}

type TLSServerHelloMsg struct {
	*TLSHelloMsg
	CipherSuite       uint16
	CompressionMethod uint8
}

func parseServiceHello(data []byte) (*TLSServerHelloMsg, error) {
	buffer := bytes.NewBuffer(data)
	var version uint16

	if err := binary.Read(buffer, binary.BigEndian, &version); err != nil {
		return nil, err
	}
	randomByte := [32]byte(buffer.Next(32))
	sessionIDLength, _ := buffer.ReadByte()
	sessionID := buffer.Next(int(sessionIDLength))
	var cipherSuite uint16
	if err := binary.Read(buffer, binary.BigEndian, &cipherSuite); err != nil {
		return nil, err
	}
	var compressionMethod uint8
	if err := binary.Read(buffer, binary.BigEndian, &compressionMethod); err != nil {
		return nil, err
	}
	var extensionsLength uint16
	if err := binary.Read(buffer, binary.BigEndian, &extensionsLength); err != nil {
		return nil, err
	}
	extensions, err := ParseBasicExtensions(buffer.Next(int(extensionsLength)))
	if err != nil {
		return nil, err
	}
	return &TLSServerHelloMsg{&TLSHelloMsg{version, randomByte, sessionID, extensions}, cipherSuite, compressionMethod}, nil
}

type TLSExtensionRaw struct {
	Type   uint16
	Length uint16
	Bytes  []byte
}

func ParseBasicExtensions(data []byte) ([]TLSExtensionRaw, error) {
	leastBytes := len(data)
	buffer := bytes.NewBuffer(data)
	var extensions []TLSExtensionRaw
	for leastBytes >= 4 {
		var extensionType uint16
		var extensionLength uint16

		if err := binary.Read(buffer, binary.BigEndian, &extensionType); err != nil {
			return nil, err
		}
		if err := binary.Read(buffer, binary.BigEndian, &extensionLength); err != nil {
			return nil, err
		}
		data := buffer.Next(int(extensionLength))
		leastBytes -= 4 + int(extensionLength)
		extensions = append(extensions, TLSExtensionRaw{extensionType, extensionLength, data})
	}
	return extensions, nil
}
