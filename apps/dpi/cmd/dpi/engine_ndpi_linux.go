//go:build linux && cgo && ndpi

package main

/*
#cgo pkg-config: libndpi
#include <stdlib.h>
#include <string.h>
#include <ndpi_api.h>

typedef struct {
	struct ndpi_global_context *global;
	struct ndpi_detection_module_struct *module;
} ds_ndpi_engine;

typedef struct {
	char protocol[128];
	char category[128];
	char confidence[64];
	int confidence_id;
	int state;
	int known;
	int risk_score;
} ds_ndpi_result;

static void *ds_malloc(size_t size) { return malloc(size); }
static void ds_free(void *ptr) { free(ptr); }
static void *ds_calloc(size_t count, size_t size) { return calloc(count, size); }
static void *ds_realloc(void *ptr, size_t size) { return realloc(ptr, size); }
static void *ds_aligned_malloc(size_t alignment, size_t size) {
	void *ptr = NULL;
	if(posix_memalign(&ptr, alignment, size) != 0) return NULL;
	return ptr;
}
static void ds_aligned_free(void *ptr) { free(ptr); }

static ds_ndpi_engine *ds_ndpi_engine_new(void) {
	ndpi_set_memory_alloction_functions(ds_malloc, ds_free, ds_calloc, ds_realloc,
		ds_aligned_malloc, ds_aligned_free, ds_malloc, ds_free);
	ds_ndpi_engine *engine = (ds_ndpi_engine *)calloc(1, sizeof(ds_ndpi_engine));
	if(engine == NULL) return NULL;
	engine->global = ndpi_global_init();
	if(engine->global == NULL) {
		free(engine);
		return NULL;
	}
	engine->module = ndpi_init_detection_module(engine->global);
	if(engine->module == NULL || ndpi_finalize_initialization(engine->module) != 0) {
		if(engine->module != NULL) ndpi_exit_detection_module(engine->module);
		ndpi_global_deinit(engine->global);
		free(engine);
		return NULL;
	}
	return engine;
}

static void ds_ndpi_engine_free(ds_ndpi_engine *engine) {
	if(engine == NULL) return;
	if(engine->module != NULL) ndpi_exit_detection_module(engine->module);
	if(engine->global != NULL) ndpi_global_deinit(engine->global);
	free(engine);
}

static struct ndpi_flow_struct *ds_ndpi_flow_new(void) {
	struct ndpi_flow_struct *flow = (struct ndpi_flow_struct *)ndpi_flow_malloc(ndpi_detection_get_sizeof_ndpi_flow_struct());
	if(flow != NULL) memset(flow, 0, ndpi_detection_get_sizeof_ndpi_flow_struct());
	return flow;
}

static void ds_ndpi_flow_free(struct ndpi_flow_struct *flow) {
	if(flow != NULL) ndpi_free_flow(flow);
}

static ds_ndpi_result ds_result(ds_ndpi_engine *engine, struct ndpi_flow_struct *flow, ndpi_protocol protocol) {
	ds_ndpi_result out;
	memset(&out, 0, sizeof(out));
	ndpi_protocol2name(engine->module, protocol.proto, out.protocol, sizeof(out.protocol));
	const char *category = ndpi_category_get_name(engine->module, protocol.category);
	const char *confidence = ndpi_confidence_get_name(flow->confidence);
	if(category != NULL) snprintf(out.category, sizeof(out.category), "%s", category);
	if(confidence != NULL) snprintf(out.confidence, sizeof(out.confidence), "%s", confidence);
	out.confidence_id = (int)flow->confidence;
	out.state = (int)protocol.state;
	out.known = protocol.proto.master_protocol != NDPI_PROTOCOL_UNKNOWN || protocol.proto.app_protocol != NDPI_PROTOCOL_UNKNOWN;
	u_int16_t client_score = 0, server_score = 0;
	out.risk_score = (int)ndpi_risk2score(flow->risk, &client_score, &server_score);
	return out;
}

static ds_ndpi_result ds_ndpi_process(ds_ndpi_engine *engine, struct ndpi_flow_struct *flow,
	const unsigned char *packet, unsigned short packet_len, unsigned long long timestamp_ms, int direction) {
	struct ndpi_flow_input_info input;
	memset(&input, 0, sizeof(input));
	input.in_pkt_dir = direction;
	input.seen_flow_beginning = NDPI_FLOW_BEGINNING_SEEN;
	ndpi_protocol protocol = ndpi_detection_process_packet(engine->module, flow, packet, packet_len, timestamp_ms, &input);
	return ds_result(engine, flow, protocol);
}

static ds_ndpi_result ds_ndpi_giveup(ds_ndpi_engine *engine, struct ndpi_flow_struct *flow) {
	ndpi_protocol protocol = ndpi_detection_giveup(engine->module, flow);
	return ds_result(engine, flow, protocol);
}

static const char *ds_ndpi_version(void) { return ndpi_revision(); }
*/
import "C"

import (
	"container/list"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unsafe"
)

type ndpiFlow struct {
	ptr      *C.struct_ndpi_flow_struct
	lastSeen time.Time
	packets  int
	seq      [2]uint32
	final    bool
	result   classifyResponse
	element  *list.Element
}

type ndpiEngine struct {
	mu          sync.Mutex
	ptr         *C.ds_ndpi_engine
	flows       map[string]*ndpiFlow
	lru         *list.List
	maxFlows    int
	flowTTL     time.Duration
	maxPackets  int
	processed   uint64
	evicted     uint64
	expired     uint64
	closed      bool
	stopCleanup chan struct{}
	cleanupDone chan struct{}
}

func newNDPIEngine(options engineOptions) (dpiEngine, error) {
	ptr := C.ds_ndpi_engine_new()
	if ptr == nil {
		return nil, errors.New("libndpi initialization failed")
	}
	engine := &ndpiEngine{
		ptr:         ptr,
		flows:       make(map[string]*ndpiFlow),
		lru:         list.New(),
		maxFlows:    options.MaxFlows,
		flowTTL:     options.FlowTTL,
		maxPackets:  options.MaxPackets,
		stopCleanup: make(chan struct{}),
		cleanupDone: make(chan struct{}),
	}
	go engine.cleanupLoop()
	return engine, nil
}

func (e *ndpiEngine) Name() string { return "ndpi" }
func (e *ndpiEngine) Version() string {
	return C.GoString(C.ds_ndpi_version())
}

func (e *ndpiEngine) Classify(ctx context.Context, req classifyRequest) (classifyResponse, error) {
	if err := ctx.Err(); err != nil {
		return classifyResponse{}, err
	}
	if len(req.Payload) == 0 {
		return classifyResponse{}, errors.New("payload is required")
	}
	packet, direction, err := synthesizePacket(req, 0)
	if err != nil {
		return classifyResponse{}, err
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return classifyResponse{}, errors.New("nDPI engine is closed")
	}
	now := time.Now()
	e.expireLocked(now)
	flowID := strings.TrimSpace(req.FlowID)
	ephemeral := flowID == ""
	if ephemeral {
		flowID = "__ephemeral__"
	}
	flow := e.flows[flowID]
	if flow == nil {
		if !ephemeral {
			e.ensureCapacityLocked()
		}
		flow = &ndpiFlow{ptr: C.ds_ndpi_flow_new(), lastSeen: now}
		if flow.ptr == nil {
			return classifyResponse{}, errors.New("nDPI flow allocation failed")
		}
		if !ephemeral {
			e.flows[flowID] = flow
			flow.element = e.lru.PushBack(flowID)
		}
	} else if flow.element != nil {
		e.lru.MoveToBack(flow.element)
	}
	if flow.final {
		flow.lastSeen = now
		return flow.result, nil
	}
	index := directionIndex(req.Direction)
	packet, direction, err = synthesizePacket(req, flow.seq[index])
	if err != nil {
		if ephemeral {
			C.ds_ndpi_flow_free(flow.ptr)
		}
		return classifyResponse{}, err
	}
	flow.seq[index] += uint32(len(req.Payload))
	flow.packets++
	flow.lastSeen = now
	e.processed++
	timestamp := req.TimestampMs
	if timestamp <= 0 {
		timestamp = now.UnixMilli()
	}
	raw := C.ds_ndpi_process(e.ptr, flow.ptr, (*C.uchar)(unsafe.Pointer(&packet[0])), C.ushort(len(packet)), C.ulonglong(timestamp), C.int(direction))
	final := int(raw.state) == 3
	if !final && flow.packets >= e.maxPackets {
		raw = C.ds_ndpi_giveup(e.ptr, flow.ptr)
		final = true
	}
	result := mapNDPIResult(raw, flow.packets, final)
	flow.final = final
	flow.result = result
	if ephemeral {
		C.ds_ndpi_flow_free(flow.ptr)
	}
	return result, nil
}

func (e *ndpiEngine) CloseFlow(flowID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.removeFlowLocked(strings.TrimSpace(flowID))
}

func (e *ndpiEngine) Stats() map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	return map[string]any{
		"flows":      len(e.flows),
		"maxFlows":   e.maxFlows,
		"maxPackets": e.maxPackets,
		"processed":  e.processed,
		"evicted":    e.evicted,
		"expired":    e.expired,
	}
}

func (e *ndpiEngine) Close() {
	select {
	case <-e.stopCleanup:
	default:
		close(e.stopCleanup)
	}
	<-e.cleanupDone
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	e.closed = true
	for id := range e.flows {
		e.removeFlowLocked(id)
	}
	C.ds_ndpi_engine_free(e.ptr)
	e.ptr = nil
}

func (e *ndpiEngine) cleanupLoop() {
	interval := e.flowTTL / 2
	if interval <= 0 || interval > 30*time.Second {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	defer close(e.cleanupDone)
	for {
		select {
		case now := <-ticker.C:
			e.mu.Lock()
			if !e.closed {
				e.expireLocked(now)
			}
			e.mu.Unlock()
		case <-e.stopCleanup:
			return
		}
	}
}

func (e *ndpiEngine) expireLocked(now time.Time) {
	for {
		oldest := e.lru.Front()
		if oldest == nil {
			return
		}
		id := oldest.Value.(string)
		flow := e.flows[id]
		if flow == nil || now.Sub(flow.lastSeen) < e.flowTTL {
			return
		}
		e.removeFlowLocked(id)
		e.expired++
	}
}

func (e *ndpiEngine) ensureCapacityLocked() {
	if len(e.flows) < e.maxFlows {
		return
	}
	if oldest := e.lru.Front(); oldest != nil {
		e.removeFlowLocked(oldest.Value.(string))
		e.evicted++
	}
}

func (e *ndpiEngine) removeFlowLocked(flowID string) {
	flow := e.flows[flowID]
	if flow == nil {
		return
	}
	delete(e.flows, flowID)
	if flow.element != nil {
		e.lru.Remove(flow.element)
	}
	C.ds_ndpi_flow_free(flow.ptr)
}

func synthesizePacket(req classifyRequest, sequence uint32) ([]byte, int, error) {
	network := normalize(req.Network)
	if network != "tcp" && network != "udp" {
		return nil, 0, errors.New("network must be tcp or udp")
	}
	source := parsePacketAddr(req.SourceIP, netip.MustParseAddr("10.0.0.1"))
	destination := parsePacketAddr(req.DestinationIP, netip.MustParseAddr("10.0.0.2"))
	sourcePort := validPort(req.SourcePort, 40000)
	destinationPort := validPort(req.DestinationPort, 443)
	direction := 1
	if normalize(req.Direction) == "server_to_client" {
		source, destination = destination, source
		sourcePort, destinationPort = destinationPort, sourcePort
		direction = 2
	}
	if source.Is6() != destination.Is6() {
		source = netip.MustParseAddr("10.0.0.1")
		destination = netip.MustParseAddr("10.0.0.2")
	}
	if source.Is6() {
		return synthesizeIPv6(network, source, destination, sourcePort, destinationPort, sequence, req.Payload), direction, nil
	}
	return synthesizeIPv4(network, source, destination, sourcePort, destinationPort, sequence, req.Payload), direction, nil
}

func synthesizeIPv4(network string, source, destination netip.Addr, sourcePort, destinationPort int, sequence uint32, payload []byte) []byte {
	l4Len := 8
	protocol := byte(17)
	if network == "tcp" {
		l4Len = 20
		protocol = 6
	}
	packet := make([]byte, 20+l4Len+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = protocol
	src := source.As4()
	dst := destination.As4()
	copy(packet[12:16], src[:])
	copy(packet[16:20], dst[:])
	writeTransportHeader(packet[20:], network, sourcePort, destinationPort, sequence, payload)
	copy(packet[20+l4Len:], payload)
	return packet
}

func synthesizeIPv6(network string, source, destination netip.Addr, sourcePort, destinationPort int, sequence uint32, payload []byte) []byte {
	l4Len := 8
	protocol := byte(17)
	if network == "tcp" {
		l4Len = 20
		protocol = 6
	}
	packet := make([]byte, 40+l4Len+len(payload))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(l4Len+len(payload)))
	packet[6] = protocol
	packet[7] = 64
	src := source.As16()
	dst := destination.As16()
	copy(packet[8:24], src[:])
	copy(packet[24:40], dst[:])
	writeTransportHeader(packet[40:], network, sourcePort, destinationPort, sequence, payload)
	copy(packet[40+l4Len:], payload)
	return packet
}

func writeTransportHeader(header []byte, network string, sourcePort, destinationPort int, sequence uint32, payload []byte) {
	binary.BigEndian.PutUint16(header[0:2], uint16(sourcePort))
	binary.BigEndian.PutUint16(header[2:4], uint16(destinationPort))
	if network == "tcp" {
		binary.BigEndian.PutUint32(header[4:8], sequence)
		header[12] = 5 << 4
		header[13] = 0x18
		binary.BigEndian.PutUint16(header[14:16], 65535)
		return
	}
	binary.BigEndian.PutUint16(header[4:6], uint16(8+len(payload)))
}

func parsePacketAddr(value string, fallback netip.Addr) netip.Addr {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return fallback
	}
	return addr.Unmap()
}

func validPort(port, fallback int) int {
	if port < 1 || port > 65535 {
		return fallback
	}
	return port
}

func directionIndex(direction string) int {
	if normalize(direction) == "server_to_client" {
		return 1
	}
	return 0
}

func mapNDPIResult(raw C.ds_ndpi_result, packets int, final bool) classifyResponse {
	protocolName := normalizedProtocolName(C.GoString(&raw.protocol[0]))
	if protocolName == "unknown" || protocolName == "unknown_unknown" {
		protocolName = "unknown"
	}
	category := normalizeNDPICategory(C.GoString(&raw.category[0]))
	category = protocolCategory(protocolName, category)
	confidenceName := normalizedProtocolName(C.GoString(&raw.confidence[0]))
	confidence := ndpiConfidence(int(raw.confidence_id), raw.known != 0)
	risk, tags := ndpiRisk(protocolName, category, int(raw.risk_score))
	tags = append(tags, "ndpi")
	if confidenceName != "" {
		tags = append(tags, "ndpi_confidence_"+confidenceName)
	}
	return classifyResponse{
		Protocol: protocolName, Category: category, Confidence: confidence,
		RiskScore: risk, RiskLevel: riskLevel(risk), Tags: tags,
		Engine: "ndpi", Final: final, Packets: packets,
	}
}

func ndpiConfidence(value int, known bool) int {
	if !known {
		return 0
	}
	switch value {
	case 1:
		return 30
	case 2:
		return 85
	case 3:
		return 50
	case 4:
		return 55
	case 5:
		return 70
	case 6:
		return 95
	case 7:
		return 75
	case 8:
		return 45
	case 9:
		return 95
	default:
		return 20
	}
}

func normalizeNDPICategory(value string) string {
	value = normalizedProtocolName(value)
	switch {
	case strings.Contains(value, "vpn"):
		return "vpn"
	case strings.Contains(value, "peer") || strings.Contains(value, "p2p"):
		return "p2p"
	case strings.Contains(value, "remote"):
		return "remote_access"
	case strings.Contains(value, "game"):
		return "gaming"
	case strings.Contains(value, "web") || strings.Contains(value, "cloud"):
		return "web"
	case value == "" || value == "unspecified":
		return "unknown"
	default:
		return value
	}
}

func ndpiRisk(protocolName, category string, engineRisk int) (int, []string) {
	// nDPI flow risks include generic security findings such as cleartext HTTP,
	// missing prior DNS, or malformed metadata. They are useful for audit but
	// must not be treated as unauthorized tunnel risk without an explicit map.
	risk := 10
	tags := make([]string, 0, 3)
	if engineRisk > 0 {
		tags = append(tags, "ndpi_flow_risk")
	}
	switch {
	case category == "vpn" || protocolMatches(protocolName, "wireguard", "openvpn", "ipsec", "tor"):
		risk = 85
		tags = append(tags, "vpn", "encrypted_tunnel")
	case category == "p2p" || protocolMatches(protocolName, "bittorrent", "edonkey"):
		risk = 90
		tags = append(tags, "p2p")
	case category == "remote_access" || protocolMatches(protocolName, "ssh", "rdp", "teamviewer", "anydesk"):
		risk = 60
		tags = append(tags, "remote_access")
	default:
		risk = 10
	}
	if risk > 100 {
		risk = 100
	}
	return risk, tags
}

func protocolCategory(protocolName, category string) string {
	switch {
	case protocolMatches(protocolName, "bittorrent", "edonkey", "gnutella"):
		return "p2p"
	case protocolMatches(protocolName, "wireguard", "openvpn", "ipsec", "tor", "tailscale", "hamachi"):
		return "vpn"
	case protocolMatches(protocolName, "ssh", "rdp", "teamviewer", "anydesk", "vnc"):
		return "remote_access"
	default:
		return category
	}
}

func protocolMatches(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if value == candidate || strings.HasPrefix(value, candidate+"_") || strings.HasSuffix(value, "_"+candidate) {
			return true
		}
	}
	return false
}
