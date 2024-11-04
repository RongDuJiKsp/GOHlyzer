package tlsextension

import mtls "GOHlyzer/service/tls"

const (
	ExtensionServiceNameFlag     uint16 = 0x0000
	ExtensionSupposedVersionFlag uint16 = 0x002b
)

type TLSExtension interface {
	Type() uint16
}
type BaseTLSExtension struct {
	rawType uint16
}

func Distinguish(raw mtls.TLSExtensionRaw) TLSExtension {
	if raw.Type == ExtensionServiceNameFlag {
		return ParseServerNameExtension(raw)
	}
	if raw.Type == ExtensionSupposedVersionFlag {
		return ParseSupposedVersionExtension(raw)
	}
	return ParseUnknownTLSExtension(raw)
}
