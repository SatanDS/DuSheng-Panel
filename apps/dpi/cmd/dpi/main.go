package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var version = "dev"

type classifyRequest struct {
	Network         string   `json:"network"`
	Payload         []byte   `json:"payload"`
	BuiltinProtocol string   `json:"builtinProtocol"`
	Host            string   `json:"host"`
	ALPN            []string `json:"alpn"`
	RuleID          uint     `json:"ruleId"`
	FlowID          string   `json:"flowId"`
	Direction       string   `json:"direction"`
	SourceIP        string   `json:"sourceIp"`
	DestinationIP   string   `json:"destinationIp"`
	SourcePort      int      `json:"sourcePort"`
	DestinationPort int      `json:"destinationPort"`
	TimestampMs     int64    `json:"timestampMs"`
}

type classifyResponse struct {
	Protocol   string   `json:"protocol"`
	Category   string   `json:"category"`
	Confidence int      `json:"confidence"`
	RiskScore  int      `json:"riskScore"`
	RiskLevel  string   `json:"riskLevel"`
	Tags       []string `json:"tags,omitempty"`
	Engine     string   `json:"engine"`
	Final      bool     `json:"final"`
	Packets    int      `json:"packets"`
}

func main() {
	logger := log.New(os.Stdout, "dusheng-dpi ", log.LstdFlags|log.Lmicroseconds)
	listen := flag.String("listen", firstEnvDefault("unix:/run/dusheng-dpi.sock", "DUSHENG_DPI_LISTEN"), "listen address, e.g. unix:/run/dusheng-dpi.sock or 127.0.0.1:19091")
	engineMode := flag.String("engine", firstEnvDefault("auto", "DUSHENG_DPI_ENGINE"), "DPI engine: auto, ndpi, or heuristic")
	maxFlows := flag.Int("max-flows", firstEnvInt(8192, "DUSHENG_DPI_MAX_FLOWS"), "maximum number of tracked DPI flows")
	flowTTL := flag.Duration("flow-ttl", firstEnvDuration(2*time.Minute, "DUSHENG_DPI_FLOW_TTL"), "idle flow retention")
	maxPackets := flag.Int("max-packets", firstEnvInt(12, "DUSHENG_DPI_MAX_PACKETS"), "maximum packets inspected per flow")
	flag.Parse()
	engine, err := openEngine(engineOptions{Mode: *engineMode, MaxFlows: *maxFlows, FlowTTL: *flowTTL, MaxPackets: *maxPackets})
	if err != nil {
		logger.Fatalf("initialize DPI engine: %v", err)
	}
	defer engine.Close()
	logger.Printf("engine=%s version=%s", engine.Name(), engine.Version())

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		respondJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": version, "engine": engine.Name(), "engineVersion": engine.Version(), "stats": engine.Stats()})
	})
	mux.HandleFunc("/classify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var req classifyRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128*1024)).Decode(&req); err != nil {
			respondJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		result, err := engine.Classify(r.Context(), req)
		if err != nil {
			respondJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
			return
		}
		respondJSON(w, http.StatusOK, result)
	})
	mux.HandleFunc("/flows/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		flowID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/flows/"))
		if flowID == "" {
			respondJSON(w, http.StatusBadRequest, map[string]any{"error": "flow id is required"})
			return
		}
		engine.CloseFlow(flowID)
		w.WriteHeader(http.StatusNoContent)
	})

	ln, err := listenOn(*listen)
	if err != nil {
		logger.Fatalf("listen: %v", err)
	}
	if strings.HasPrefix(*listen, "unix:") {
		_ = os.Chmod(strings.TrimPrefix(*listen, "unix:"), 0o660)
	}
	server := &http.Server{
		Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	logger.Printf("listening on %s", *listen)
	if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
		logger.Fatalf("serve: %v", err)
	}
}

func listenOn(address string) (net.Listener, error) {
	address = strings.TrimSpace(address)
	if strings.HasPrefix(address, "unix:") {
		path := strings.TrimPrefix(address, "unix:")
		_ = os.Remove(path)
		return net.Listen("unix", path)
	}
	return net.Listen("tcp", address)
}

func classify(req classifyRequest) classifyResponse {
	payload := req.Payload
	builtin := normalize(req.BuiltinProtocol)
	switch {
	case builtin == "ssh" || bytes.HasPrefix(payload, []byte("SSH-")):
		return verdict("ssh", "remote_access", 100, 60, "remote_access", "encrypted_tunnel")
	case builtin == "socks" || looksSOCKS(payload):
		return verdict("socks", "proxy", 100, 90, "proxy")
	case builtin == "http_connect" || hasPrefixFold(payload, "CONNECT "):
		return verdict("http_connect", "proxy", 100, 90, "proxy")
	case looksBitTorrent(payload):
		return verdict("bittorrent", "p2p", 95, 95, "p2p")
	case looksWireGuard(req.Network, payload):
		return verdict("wireguard", "vpn", 80, 85, "vpn", "encrypted_tunnel")
	case looksOpenVPN(req.Network, payload):
		return verdict("openvpn_like", "vpn", 45, 45, "vpn_candidate", "heuristic_low_confidence")
	case builtin == "quic":
		return verdict("quic", "web", 90, 20, "encrypted")
	case builtin == "tls":
		return verdict("tls", "web", 95, 15, "encrypted")
	case builtin == "http":
		return verdict("http", "web", 100, 5)
	case highEntropy(payload):
		return verdict("unknown_encrypted", "encrypted_tunnel", 45, 45, "encrypted")
	default:
		return verdict("unknown", "unknown", 30, 10)
	}
}

func verdict(protocol, category string, confidence, risk int, tags ...string) classifyResponse {
	return classifyResponse{
		Protocol:   protocol,
		Category:   category,
		Confidence: confidence,
		RiskScore:  risk,
		RiskLevel:  riskLevel(risk),
		Tags:       tags,
	}
}

func looksSOCKS(payload []byte) bool {
	if len(payload) < 2 {
		return false
	}
	if payload[0] == 0x05 {
		methods := int(payload[1])
		return methods > 0 && len(payload) >= 2+methods
	}
	return payload[0] == 0x04 && (payload[1] == 0x01 || payload[1] == 0x02)
}

func looksBitTorrent(payload []byte) bool {
	return bytes.Contains(payload, []byte("BitTorrent protocol")) ||
		bytes.Contains(bytes.ToLower(payload), []byte("info_hash=")) ||
		bytes.Contains(bytes.ToLower(payload), []byte("peer_id="))
}

func looksWireGuard(network string, payload []byte) bool {
	if normalize(network) != "udp" || len(payload) < 4 {
		return false
	}
	msgType := binary.LittleEndian.Uint32(payload[:4])
	switch msgType {
	case 1:
		return len(payload) == 148
	case 2:
		return len(payload) == 92
	case 3:
		return len(payload) == 64
	case 4:
		return len(payload) >= 32
	default:
		return false
	}
}

func looksOpenVPN(network string, payload []byte) bool {
	if normalize(network) != "udp" || len(payload) < 2 {
		return false
	}
	opcode := payload[0] >> 3
	return opcode >= 1 && opcode <= 8 && len(payload) >= 14
}

func highEntropy(payload []byte) bool {
	if len(payload) < 32 {
		return false
	}
	var seen [256]bool
	var unique int
	for _, b := range payload {
		if !seen[b] {
			seen[b] = true
			unique++
		}
	}
	return unique > len(payload)/2
}

func hasPrefixFold(payload []byte, prefix string) bool {
	if len(payload) < len(prefix) {
		return false
	}
	return strings.EqualFold(string(payload[:len(prefix)]), prefix)
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

func normalize(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, "-", "_")
	return value
}

func respondJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func firstEnvDefault(def string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return def
}

func firstEnvInt(def int, keys ...string) int {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			var parsed int
			if _, err := fmt.Sscanf(value, "%d", &parsed); err == nil && parsed > 0 {
				return parsed
			}
		}
	}
	return def
}

func firstEnvDuration(def time.Duration, keys ...string) time.Duration {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			if parsed, err := time.ParseDuration(value); err == nil && parsed > 0 {
				return parsed
			}
		}
	}
	return def
}
