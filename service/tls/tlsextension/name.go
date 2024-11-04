package tlsextension

import (
	"strconv"
)

var tlsExtensions = map[uint16]string{
	0:      "server_name",
	1:      "max_fragment_length",
	2:      "client_certificate_url",
	3:      "trusted_ca_keys",
	4:      "truncated_hmac",
	5:      "status_request",
	6:      "user_mapping",
	7:      "client_authz",
	8:      "server_authz",
	9:      "cert_type",
	10:     "supported_groups",
	11:     "ec_point_formats",
	12:     "srp",
	13:     "signature_algorithms",
	14:     "use_srtp",
	15:     "heartbeat",
	16:     "application_layer_protocol_negotiation",
	17:     "status_request_v2",
	18:     "signed_certificate_timestamp",
	19:     "client_certificate_type",
	20:     "server_certificate_type",
	21:     "padding",
	22:     "encrypt_then_mac",
	23:     "extended_master_secret",
	24:     "token_binding",
	25:     "cached_info",
	26:     "tls_lts",
	27:     "compress_certificate",
	28:     "record_size_limit",
	29:     "pwd_protect",
	30:     "pwd_clear",
	31:     "password_salt",
	32:     "ticket_pinning",
	33:     "tls_cert_with_extern_psk",
	34:     "delegated_credential",
	35:     "session_ticket",
	36:     "TLMSP",
	37:     "TLMSP_proxying",
	38:     "TLMSP_delegate",
	39:     "supported_ekt_ciphers",
	41:     "pre_shared_key",
	42:     "early_data",
	43:     "supported_versions",
	44:     "cookie",
	45:     "psk_key_exchange_modes",
	47:     "certificate_authorities",
	48:     "oid_filters",
	49:     "post_handshake_auth",
	50:     "signature_algorithms_cert",
	51:     "key_share",
	52:     "transparency_info",
	53:     "connection_id_deprecated",
	54:     "connection_id",
	55:     "external_id_hash",
	56:     "external_session_id",
	57:     "quic_transport_parameters",
	58:     "ticket_request",
	59:     "dnssec_chain",
	60:     "sequence_number_encryption_algorithms",
	61:     "rrc",
	0x1001: "draft-rescorla-tls-esni-01",
	0xff01: "GREASE",
}

func FindExtensionNameFromID(id uint16) string {
	if tlsExtensions[id] == "" {
		return strconv.FormatUint(uint64(id), 16)
	}
	return tlsExtensions[id]
}
