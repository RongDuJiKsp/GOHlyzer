package tlsextension

import mtls "GOHlyzer/service/tls"

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
