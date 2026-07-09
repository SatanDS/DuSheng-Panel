package protocol

import (
	"bytes"
	"encoding/binary"
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
	Protocol    string
	Action      string
	Reason      string
	Host        string
	ALPN        []string
	MatchedRule string
}

func Detect(firstPacket []byte, policy Policy) Result {
	result := Inspect(firstPacket)
	name := result.Protocol
	violated, reason := violatesPolicy(name, policy)
	if !violated {
		result.Action = ActionAllow
		return result
	}
	result.Action = normalizeMode(policy.Mode)
	result.Reason = reason
	result.MatchedRule = reason
	return result
}

func Inspect(firstPacket []byte) Result {
	if isTLSClientHello(firstPacket) {
		host, alpn := parseTLSClientHello(firstPacket)
		return Result{Protocol: NameTLS, Host: host, ALPN: alpn}
	}
	if isQUICInitial(firstPacket) {
		return Result{Protocol: NameQUIC}
	}
	if bytes.HasPrefix(firstPacket, []byte("SSH-")) {
		return Result{Protocol: NameSSH}
	}
	if isSOCKS(firstPacket) {
		return Result{Protocol: NameSOCKS}
	}
	if isHTTPConnect(firstPacket) {
		return Result{Protocol: NameHTTPConnect, Host: parseHTTPHost(firstPacket)}
	}
	if isHTTP(firstPacket) {
		return Result{Protocol: NameHTTP, Host: parseHTTPHost(firstPacket)}
	}
	return Result{Protocol: NameUnknown}
}

func Identify(firstPacket []byte) string {
	return Inspect(firstPacket).Protocol
}

func isTLSClientHello(packet []byte) bool {
	return len(packet) >= 6 &&
		packet[0] == 0x16 &&
		packet[1] == 0x03 &&
		packet[2] <= 0x04 &&
		packet[5] == 0x01
}

func parseTLSClientHello(packet []byte) (string, []string) {
	if len(packet) < 9 {
		return "", nil
	}
	recordLen := int(binary.BigEndian.Uint16(packet[3:5]))
	recordEnd := minInt(len(packet), 5+recordLen)
	if recordEnd < 9 || packet[5] != 0x01 {
		return "", nil
	}
	helloLen := int(packet[6])<<16 | int(packet[7])<<8 | int(packet[8])
	helloEnd := minInt(recordEnd, 9+helloLen)
	if helloEnd < 9+2+32+1 {
		return "", nil
	}

	offset := 9
	offset += 2 + 32
	if offset >= helloEnd {
		return "", nil
	}
	sessionLen := int(packet[offset])
	offset++
	if offset+sessionLen+2 > helloEnd {
		return "", nil
	}
	offset += sessionLen

	cipherLen := int(binary.BigEndian.Uint16(packet[offset : offset+2]))
	offset += 2
	if offset+cipherLen+1 > helloEnd {
		return "", nil
	}
	offset += cipherLen

	compressionLen := int(packet[offset])
	offset++
	if offset+compressionLen+2 > helloEnd {
		return "", nil
	}
	offset += compressionLen

	extensionsLen := int(binary.BigEndian.Uint16(packet[offset : offset+2]))
	offset += 2
	extensionsEnd := minInt(helloEnd, offset+extensionsLen)

	var host string
	var alpn []string
	for offset+4 <= extensionsEnd {
		extType := binary.BigEndian.Uint16(packet[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(packet[offset+2 : offset+4]))
		offset += 4
		if offset+extLen > extensionsEnd {
			break
		}
		ext := packet[offset : offset+extLen]
		switch extType {
		case 0:
			if value := parseSNIExtension(ext); value != "" {
				host = value
			}
		case 16:
			alpn = parseALPNExtension(ext)
		}
		offset += extLen
	}
	return host, alpn
}

func parseSNIExtension(ext []byte) string {
	if len(ext) < 5 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(ext[0:2]))
	offset := 2
	end := minInt(len(ext), offset+listLen)
	for offset+3 <= end {
		nameType := ext[offset]
		nameLen := int(binary.BigEndian.Uint16(ext[offset+1 : offset+3]))
		offset += 3
		if offset+nameLen > end {
			return ""
		}
		if nameType == 0 {
			return string(ext[offset : offset+nameLen])
		}
		offset += nameLen
	}
	return ""
}

func parseALPNExtension(ext []byte) []string {
	if len(ext) < 3 {
		return nil
	}
	listLen := int(binary.BigEndian.Uint16(ext[0:2]))
	offset := 2
	end := minInt(len(ext), offset+listLen)
	var values []string
	for offset < end {
		nameLen := int(ext[offset])
		offset++
		if nameLen == 0 || offset+nameLen > end {
			return values
		}
		values = append(values, string(ext[offset:offset+nameLen]))
		offset += nameLen
	}
	return values
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

func parseHTTPHost(packet []byte) string {
	headerEnd := bytes.Index(packet, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		headerEnd = bytes.Index(packet, []byte("\n\n"))
	}
	if headerEnd < 0 {
		headerEnd = minInt(len(packet), 2048)
	}
	text := string(packet[:headerEnd])
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	if len(lines) > 0 && strings.HasPrefix(strings.ToUpper(lines[0]), "CONNECT ") {
		parts := strings.Fields(lines[0])
		if len(parts) >= 2 {
			return strings.TrimSpace(parts[1])
		}
	}
	for _, line := range lines[1:] {
		name, value, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(name), "host") {
			return strings.TrimSpace(value)
		}
	}
	return ""
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

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
