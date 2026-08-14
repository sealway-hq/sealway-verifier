// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

// Package pdfconfig centralises the one piece of global state the PDF library
// requires.
//
// pdfcpu decides where to look for an on-disk configuration directory through a
// package level variable. The verifier must behave identically on every host,
// must not require a writable filesystem and must stay usable from a WebAssembly
// build, so that lookup is disabled. Routing the assignment through a single
// guarded setter keeps it free of data races when several packages configure the
// library concurrently.
package pdfconfig

import (
	"sync"

	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

var once sync.Once

// Disable turns off the pdfcpu on-disk configuration directory.
//
// It is safe for concurrent use and takes effect exactly once. It must be called
// before building a pdfcpu configuration.
func Disable() {
	once.Do(func() { model.ConfigPath = "disable" })
}

// NewConfiguration returns a pdfcpu configuration with the on-disk configuration
// directory disabled.
func NewConfiguration() *model.Configuration {
	Disable()

	return model.NewDefaultConfiguration()
}
