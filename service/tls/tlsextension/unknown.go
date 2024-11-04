package tlsextension

import mtls "dns-tunnel-flowcatcher/util/tls"

type UnknownTLSExtension struct {
	BaseTLSExtension
	bin []byte
}

func ParseUnknownTLSExtension(raw mtls.TLSExtensionRaw) *UnknownTLSExtension {
	return &UnknownTLSExtension{BaseTLSExtension{raw.Type}, raw.Bytes}
}
func (u *UnknownTLSExtension) Bin() []byte {
	return u.bin
}

func (u *UnknownTLSExtension) Type() uint16 {
	return u.rawType
}
