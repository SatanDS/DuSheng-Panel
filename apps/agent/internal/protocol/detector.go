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
	ActionLimit   = "limit"
	ActionBlock   = "block"
)

type Policy struct {
	Template                string
	Purpose                 string
	InspectionLevel         string
	Network                 string
	Mode                    string
	BlockTLS                bool
	BlockQUIC               bool
	AllowPlainTCPOnly       bool
	AllowHTTPOnly           bool
	BlockProxyLike          bool
	BlockEncryptedTunnel    bool
	ObservationMinutes      int
	AuthorizedProtocols     string
	BlockedProtocolGroups   string
	HostAllowlist           string
	HostBlocklist           string
	SNIAllowlist            string
	SNIBlocklist            string
	ALPNAllowlist           string
	ALPNBlocklist           string
	TLSNoSNIAction          string
	QUICAction              string
	SSHAction               string
	UnknownTCPAction        string
	UnknownUDPAction        string
	NDPILowConfidenceAction string
	DPITimeoutMs            int
}

type Result struct {
	Protocol     string
	Action       string
	Reason       string
	Host         string
	ALPN         []string
	MatchedRule  string
	Source       string
	Confidence   int
	RiskScore    int
	RiskLevel    string
	Tags         []string
	NDPIProtocol string
	NDPICategory string
}

type DPIResult struct {
	Protocol   string
	Category   string
	Confidence int
	RiskScore  int
	RiskLevel  string
	Tags       []string
}

func Detect(firstPacket []byte, policy Policy) Result {
	result := Inspect(firstPacket)
	return ApplyPolicy(result, policy)
}

func ApplyPolicy(result Result, policy Policy) Result {
	result.Source = "builtin"
	result.Confidence = 100
	result.RiskLevel = riskLevel(result.RiskScore)
	result.Action = ActionAllow

	if matched := firstHostMatch(result.Host, policy.HostAllowlist, policy.SNIAllowlist); matched != "" {
		result.MatchedRule = "host allowlist: " + matched
		result.Reason = "host is allowlisted"
		return result
	}
	if matched := firstHostMatch(result.Host, policy.HostBlocklist, policy.SNIBlocklist); matched != "" {
		return markViolation(result, actionOrMode(policy.Mode, ActionBlock), "host is blocklisted", "host blocklist: "+matched)
	}
	if matched := firstALPNMatch(result.ALPN, policy.ALPNAllowlist); matched != "" {
		result.MatchedRule = "alpn allowlist: " + matched
		result.Reason = "alpn is allowlisted"
		return result
	}
	if matched := firstALPNMatch(result.ALPN, policy.ALPNBlocklist); matched != "" {
		return markViolation(result, actionOrMode(policy.Mode, ActionBlock), "alpn is blocklisted", "alpn blocklist: "+matched)
	}

	if violated, reason := violatesLegacyPolicy(result.Protocol, policy); violated {
		return markViolation(result, actionOrMode(policy.Mode, ActionBlock), reason, reason)
	}

	if result.Protocol == NameTLS && result.Host == "" {
		if action := normalizeOptionalAction(policy.TLSNoSNIAction); action != "" && action != ActionAllow {
			return markViolation(result, action, "tls has no sni", "tls_no_sni")
		}
	}
	switch result.Protocol {
	case NameQUIC:
		if action := actionWithPurposeDefault(policy.QUICAction, policy, ActionAllow); action != ActionAllow {
			return markViolation(result, action, "quic matched policy action", "quic_action")
		}
	case NameSSH:
		if action := actionWithPurposeDefault(policy.SSHAction, policy, defaultSSHAction(policy)); action != ActionAllow {
			return markViolation(result, action, "ssh matched policy action", "ssh_action")
		}
	case NameUnknown:
		if authorizedUnknown(policy) {
			result.MatchedRule = "authorized encrypted entry"
			result.Reason = "unknown first packet is allowed for authorized protocol entry"
			return result
		}
		action := policy.UnknownTCPAction
		if strings.EqualFold(policy.Network, "udp") {
			action = policy.UnknownUDPAction
		}
		if normalized := actionWithPurposeDefault(action, policy, defaultUnknownAction(policy)); normalized != ActionAllow {
			return markViolation(result, normalized, "unknown protocol matched policy action", "unknown_action")
		}
	}

	return result
}

func ApplyDPI(result Result, policy Policy, dpi DPIResult) Result {
	if strings.TrimSpace(dpi.Protocol) == "" && strings.TrimSpace(dpi.Category) == "" {
		return result
	}
	result.Source = "ndpi"
	result.NDPIProtocol = normalizeToken(dpi.Protocol)
	result.NDPICategory = normalizeToken(dpi.Category)
	result.Confidence = dpi.Confidence
	result.RiskScore = dpi.RiskScore
	result.RiskLevel = defaultString(strings.TrimSpace(dpi.RiskLevel), riskLevel(dpi.RiskScore))
	result.Tags = appendUnique(result.Tags, dpi.Tags...)

	if result.Confidence > 0 && result.Confidence < 50 {
		action := actionWithPurposeDefault(policy.NDPILowConfidenceAction, policy, defaultLowConfidenceAction(policy))
		if action != ActionAllow {
			return markViolation(result, action, "ndpi confidence is low", "ndpi_low_confidence")
		}
		return result
	}

	if blockedGroup := matchedBlockedGroup(policy.BlockedProtocolGroups, result.NDPIProtocol, result.NDPICategory, result.Tags); blockedGroup != "" {
		return markViolation(result, actionOrMode(policy.Mode, ActionBlock), "ndpi matched blocked protocol group", "ndpi_group:"+blockedGroup)
	}
	if result.RiskScore >= 80 {
		return markViolation(result, actionOrMode(policy.Mode, ActionBlock), "ndpi high risk protocol", "ndpi_high_risk")
	}
	if result.RiskScore >= 50 {
		return markViolation(result, actionOrMode(policy.Mode, ActionAlert), "ndpi medium risk protocol", "ndpi_medium_risk")
	}
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

func violatesLegacyPolicy(name string, policy Policy) (bool, string) {
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

func markViolation(result Result, action, reason, matched string) Result {
	result.Action = actionOrMode(action, ActionBlock)
	result.Reason = reason
	result.MatchedRule = matched
	return result
}

func normalizeOptionalAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case ActionAllow:
		return ActionAllow
	case ActionObserve:
		return ActionObserve
	case ActionAlert:
		return ActionAlert
	case ActionLimit:
		return ActionLimit
	case ActionBlock:
		return ActionBlock
	default:
		return ""
	}
}

func actionOrMode(action, fallback string) string {
	if normalized := normalizeOptionalAction(action); normalized != "" {
		if normalized == ActionAllow {
			return ActionAllow
		}
		return normalized
	}
	if normalized := normalizeOptionalAction(fallback); normalized != "" {
		if normalized == ActionAllow {
			return ActionAllow
		}
		return normalized
	}
	return ActionBlock
}

func actionWithPurposeDefault(action string, policy Policy, fallback string) string {
	if normalized := normalizeOptionalAction(action); normalized != "" {
		return normalized
	}
	return actionOrMode(fallback, ActionAllow)
}

func defaultSSHAction(policy Policy) string {
	switch policyPurpose(policy) {
	case "ssh_ops", "ssh", "ops_ssh":
		return ActionAllow
	case "gaming", "authorized_ss", "daily", "normal", "strict":
		return ActionBlock
	default:
		return ActionAllow
	}
}

func defaultUnknownAction(policy Policy) string {
	if strings.EqualFold(policy.Network, "udp") {
		switch policyPurpose(policy) {
		case "strict":
			return ActionAlert
		default:
			return ActionAllow
		}
	}
	switch policyPurpose(policy) {
	case "authorized_ss", "gaming", "daily":
		return ActionAllow
	case "strict":
		return ActionAlert
	default:
		return ActionAllow
	}
}

func defaultLowConfidenceAction(policy Policy) string {
	switch policyPurpose(policy) {
	case "strict":
		return ActionAlert
	default:
		return ActionAllow
	}
}

func policyPurpose(policy Policy) string {
	if value := normalizeToken(policy.Purpose); value != "" {
		return value
	}
	switch normalizeToken(policy.Template) {
	case "game_acceleration", "gaming":
		return "gaming"
	case "authorized_ss", "ss_proxy", "shadowsocks":
		return "authorized_ss"
	case "ssh_ops", "ssh":
		return "ssh_ops"
	case "daily", "daily_browsing":
		return "daily"
	case "strict", "strict_compliance", "iepl_iplc_no_tls":
		return "strict"
	case "normal", "plain_tcp_only", "http_only", "block_proxy_like":
		return "normal"
	default:
		return "custom"
	}
}

func authorizedUnknown(policy Policy) bool {
	purpose := policyPurpose(policy)
	if purpose == "authorized_ss" {
		return true
	}
	return containsAnyToken(policy.AuthorizedProtocols, "ss", "shadowsocks", "shadowsocks2022", "ss2022", "2022-blake3-aes-256-gcm")
}

func firstHostMatch(host string, lists ...string) string {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return ""
	}
	if withoutPort, _, ok := strings.Cut(host, ":"); ok {
		host = strings.TrimSuffix(withoutPort, ".")
	}
	for _, list := range lists {
		for _, pattern := range splitList(list) {
			if matchHost(host, pattern) {
				return pattern
			}
		}
	}
	return ""
}

func matchHost(host, pattern string) bool {
	pattern = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(pattern), "."))
	if pattern == "" {
		return false
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(host, suffix) && host != strings.TrimPrefix(suffix, ".")
	}
	return host == pattern
}

func firstALPNMatch(values []string, list string) string {
	for _, value := range values {
		needle := normalizeToken(value)
		for _, pattern := range splitList(list) {
			if needle == normalizeToken(pattern) {
				return pattern
			}
		}
	}
	return ""
}

func matchedBlockedGroup(groups, protocolName, category string, tags []string) string {
	for _, group := range splitList(groups) {
		group = normalizeToken(group)
		if group == "" {
			continue
		}
		if group == protocolName || group == category {
			return group
		}
		for _, tag := range tags {
			if group == normalizeToken(tag) {
				return group
			}
		}
		switch group {
		case "proxy":
			if containsAny(protocolName, "socks", "http_connect", "shadowsocks", "v2ray", "xray", "trojan") {
				return group
			}
		case "vpn":
			if containsAny(protocolName, "wireguard", "openvpn", "ipsec", "pptp", "l2tp", "hysteria", "tuic") {
				return group
			}
		case "p2p", "bt", "bittorrent":
			if containsAny(protocolName, "bittorrent", "bt") || containsAny(category, "p2p") {
				return group
			}
		case "remote_access":
			if containsAny(protocolName, "ssh", "rdp", "vnc", "teamviewer", "anydesk") || containsAny(category, "remote") {
				return group
			}
		case "encrypted_tunnel":
			if containsAny(protocolName, "wireguard", "openvpn", "hysteria", "tuic", "trojan") || containsAny(category, "vpn", "proxy", "tunnel") {
				return group
			}
		}
	}
	return ""
}

func containsAnyToken(list string, needles ...string) bool {
	values := splitList(list)
	for _, value := range values {
		normalized := normalizeToken(value)
		for _, needle := range needles {
			if normalized == normalizeToken(needle) {
				return true
			}
		}
	}
	return false
}

func containsAny(value string, needles ...string) bool {
	value = normalizeToken(value)
	for _, needle := range needles {
		if strings.Contains(value, normalizeToken(needle)) {
			return true
		}
	}
	return false
}

func splitList(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ';' || r == ' ' || r == '\t'
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func normalizeToken(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "-", "_")
	value = strings.ReplaceAll(value, " ", "_")
	return value
}

func appendUnique(values []string, more ...string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		seen[normalizeToken(value)] = true
	}
	for _, value := range more {
		key := normalizeToken(value)
		if key == "" || seen[key] {
			continue
		}
		values = append(values, value)
		seen[key] = true
	}
	return values
}

func riskLevel(score int) string {
	switch {
	case score >= 80:
		return "high"
	case score >= 50:
		return "medium"
	case score > 0:
		return "low"
	default:
		return ""
	}
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return value
	}
	return fallback
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
