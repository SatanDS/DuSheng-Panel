//go:build !linux || !cgo || !ndpi

package main

import "errors"

func newNDPIEngine(engineOptions) (dpiEngine, error) {
	return nil, errors.New("binary was built without Linux CGO tag ndpi")
}
