package protocol

import (
	"bytes"
	"strings"
)

const (
	NameTLS         = "tls"
	NameQUIC        = "quic"
	NameHTTP        = "http"
	NameSSH         = "ssh"
	NameSOCKS       = "socks"
	NameHTTPConnect = "http_connect"
	NameUnknown     = "unknown"

	ActionAllow   = "allow"
	ActionObserve = "observe"
	ActionAlert   = "alert"
	ActionBlock   = "block"
)

type Policy struct {
	Mode                 string
	BlockTLS             bool
	BlockQUIC            bool
	AllowPlainTCPOnly    bool
	AllowHTTPOnly        bool
	BlockProxyLike       bool
	BlockEncryptedTunnel bool
}

type Result struct {
	Protocol string
	Action   string
	Reason   string
}

func Detect(firstPacket []byte, policy Policy) Result {
	name := Identify(firstPacket)
	violated, reason := violatesPolicy(name, policy)
	if !violated {
		return Result{Protocol: name, Action: ActionAllow}
	}
	return Result{Protocol: name, Action: normalizeMode(policy.Mode), Reason: reason}
}

func Identify(firstPacket []byte) string {
	if isTLSClientHello(firstPacket) {
		return NameTLS
	}
	if isQUICInitial(firstPacket) {
		return NameQUIC
	}
	if bytes.HasPrefix(firstPacket, []byte("SSH-")) {
		return NameSSH
	}
	if isSOCKS(firstPacket) {
		return NameSOCKS
	}
	if isHTTPConnect(firstPacket) {
		return NameHTTPConnect
	}
	if isHTTP(firstPacket) {
		return NameHTTP
	}
	return NameUnknown
}

func isTLSClientHello(packet []byte) bool {
	return len(packet) >= 6 &&
		packet[0] == 0x16 &&
		packet[1] == 0x03 &&
		packet[2] <= 0x04 &&
		packet[5] == 0x01
}

func isQUICInitial(packet []byte) bool {
	if len(packet) < 6 {
		return false
	}
	longHeader := packet[0]&0x80 != 0
	fixedBit := packet[0]&0x40 != 0
	if !longHeader || !fixedBit {
		return false
	}
	version := uint32(packet[1])<<24 | uint32(packet[2])<<16 | uint32(packet[3])<<8 | uint32(packet[4])
	return version != 0
}

func isSOCKS(packet []byte) bool {
	if len(packet) < 2 {
		return false
	}
	if packet[0] == 0x05 {
		methodCount := int(packet[1])
		return methodCount > 0 && len(packet) >= 2+methodCount
	}
	if packet[0] == 0x04 {
		return packet[1] == 0x01 || packet[1] == 0x02
	}
	return false
}

func isHTTPConnect(packet []byte) bool {
	return hasASCIIPrefix(packet, "CONNECT ")
}

func isHTTP(packet []byte) bool {
	methods := [...]string{
		"GET ",
		"POST ",
		"PUT ",
		"PATCH ",
		"DELETE ",
		"HEAD ",
		"OPTIONS ",
		"TRACE ",
		"HTTP/",
	}
	for _, method := range methods {
		if hasASCIIPrefix(packet, method) {
			return true
		}
	}
	return false
}

func hasASCIIPrefix(packet []byte, prefix string) bool {
	if len(packet) < len(prefix) {
		return false
	}
	return strings.EqualFold(string(packet[:len(prefix)]), prefix)
}

func violatesPolicy(name string, policy Policy) (bool, string) {
	switch {
	case policy.BlockTLS && name == NameTLS:
		return true, "tls is blocked"
	case policy.BlockQUIC && name == NameQUIC:
		return true, "quic is blocked"
	case policy.BlockProxyLike && (name == NameSOCKS || name == NameHTTPConnect):
		return true, "proxy-like protocol is blocked"
	case policy.BlockEncryptedTunnel && (name == NameTLS || name == NameQUIC || name == NameSSH):
		return true, "encrypted tunnel protocol is blocked"
	case policy.AllowHTTPOnly && name != NameHTTP:
		return true, "only http is allowed"
	case policy.AllowPlainTCPOnly && name != NameUnknown:
		return true, "only plain tcp is allowed"
	default:
		return false, ""
	}
}

func normalizeMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case ActionObserve:
		return ActionObserve
	case ActionAlert:
		return ActionAlert
	case ActionBlock, "":
		return ActionBlock
	default:
		return ActionBlock
	}
}
