package main

import (
	"context"
	"fmt"
	"strings"
	"time"
)

type engineOptions struct {
	Mode       string
	MaxFlows   int
	FlowTTL    time.Duration
	MaxPackets int
}

type dpiEngine interface {
	Name() string
	Version() string
	Classify(context.Context, classifyRequest) (classifyResponse, error)
	CloseFlow(string)
	Stats() map[string]any
	Close()
}

type heuristicEngine struct{}

func openEngine(options engineOptions) (dpiEngine, error) {
	mode := normalize(options.Mode)
	if mode == "" {
		mode = "auto"
	}
	if options.MaxFlows <= 0 {
		options.MaxFlows = 8192
	}
	if options.FlowTTL <= 0 {
		options.FlowTTL = 2 * time.Minute
	}
	if options.MaxPackets <= 0 {
		options.MaxPackets = 12
	}

	switch mode {
	case "auto":
		if engine, err := newNDPIEngine(options); err == nil {
			return engine, nil
		}
		return &heuristicEngine{}, nil
	case "ndpi":
		engine, err := newNDPIEngine(options)
		if err != nil {
			return nil, fmt.Errorf("nDPI engine is unavailable: %w", err)
		}
		return engine, nil
	case "heuristic":
		return &heuristicEngine{}, nil
	default:
		return nil, fmt.Errorf("unsupported DPI engine %q", options.Mode)
	}
}

func (e *heuristicEngine) Name() string    { return "heuristic" }
func (e *heuristicEngine) Version() string { return "builtin" }

func (e *heuristicEngine) Classify(_ context.Context, req classifyRequest) (classifyResponse, error) {
	result := classify(req)
	result.Engine = e.Name()
	result.Final = true
	result.Packets = 1
	return result, nil
}

func (e *heuristicEngine) CloseFlow(string)      {}
func (e *heuristicEngine) Stats() map[string]any { return map[string]any{"flows": 0} }
func (e *heuristicEngine) Close()                {}

func normalizedProtocolName(value string) string {
	value = normalize(value)
	value = strings.ReplaceAll(value, ".", "_")
	value = strings.ReplaceAll(value, "/", "_")
	value = strings.Join(strings.Fields(value), "_")
	return strings.Trim(value, "_")
}
