// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

//go:build js && wasm

// Command sealway-verifier-wasm exposes the Sealway proof verifier to a browser.
//
// It is a thin adapter, exactly like the command line interface: it converts
// between JavaScript values and the verifier API, and takes no verification
// decision of its own. The proof never leaves the page, and nothing is uploaded
// anywhere.
//
// The trust material used to establish qualified eIDAS status is handed in by
// the host rather than fetched here, because the official European endpoints
// send no cross-origin headers and a browser therefore cannot read them. The
// host passes the same signed documents read from a mirror, and this module
// still verifies their European signatures itself, so the mirror carries the
// bytes without becoming an authority.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"syscall/js"
	"time"

	"github.com/sealway-hq/sealway-verifier/packages/verifier"
	"github.com/sealway-hq/sealway-verifier/packages/verifier/trust"
)

func main() {
	register()

	// The Go runtime must stay alive for the exported functions to remain
	// callable.
	select {}
}

// register publishes the module's API on the global object.
//
// It is separate from main so that a test can install the very API a page
// consumes and drive it through JavaScript, rather than calling the Go
// functions behind it directly.
func register() {
	js.Global().Set("sealwayVerifier", js.ValueOf(map[string]any{
		"verify":        js.FuncOf(verify),
		"schemaVersion": verifier.ReportSchemaVersion,
	}))
}

// verify checks a proof and resolves with the canonical report as JSON.
//
// It is called as verify(proof, options) and returns a Promise. The work runs on
// a goroutine so that the Go scheduler keeps yielding to the browser event loop
// rather than blocking the page for the duration.
func verify(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return rejected("verify expects the proof as its first argument")
	}

	proof, err := toBytes(args[0])
	if err != nil {
		return rejected(err.Error())
	}

	var options js.Value
	if len(args) > 1 {
		options = args[1]
	}

	opts, err := buildOptions(options)
	if err != nil {
		return rejected(err.Error())
	}

	return promise(func() (any, error) {
		report, err := verifier.New(opts...).
			VerifyBundle(context.Background(), bytes.NewReader(proof), int64(len(proof)))
		if err != nil {
			return nil, err
		}

		encoded, err := json.Marshal(report)
		if err != nil {
			return nil, err
		}

		return string(encoded), nil
	})
}

// buildOptions reads the options object the host supplied.
func buildOptions(o js.Value) ([]verifier.Option, error) {
	opts := []verifier.Option{}

	if o.IsUndefined() || o.IsNull() {
		return append(opts, verifier.WithOffline()), nil
	}

	// Anchors are only read when the host asks for it: the public blockchain
	// endpoints may or may not allow a cross-origin request, and a page that
	// cannot reach them should skip the check rather than appear broken.
	if b := o.Get("verifyAnchors"); b.Truthy() {
		opts = append(opts, verifier.WithBlockchainVerification(true))
	} else {
		opts = append(opts, verifier.WithOffline())
	}

	if t := o.Get("timeoutSeconds"); t.Type() == js.TypeNumber && t.Float() > 0 {
		opts = append(opts, verifier.WithNetworkTimeout(time.Duration(t.Float())*time.Second))
	}

	material, err := toMaterial(o.Get("trust"))
	if err != nil {
		return nil, err
	}

	if material != nil {
		opts = append(opts, verifier.WithTrustProvider(
			trust.NewStatic(material, "trust material supplied by the page")))
	}

	return opts, nil
}

// toMaterial converts the trust material object the host supplied.
//
// The host is expected to pass the official signed documents unchanged; their
// signatures are verified here, so material from a mirror is checked exactly
// like material read from the official publication.
func toMaterial(v js.Value) (*trust.Material, error) {
	if v.IsUndefined() || v.IsNull() {
		return nil, nil
	}

	lotl, err := toBytes(v.Get("lotl"))
	if err != nil {
		return nil, fmt.Errorf("trust.lotl: %w", err)
	}

	if len(lotl) == 0 {
		return nil, nil
	}

	material := &trust.Material{
		LOTL:        lotl,
		Lists:       map[string][]byte{},
		Source:      "trust material supplied by the page",
		RetrievedAt: time.Now().UTC(),
	}

	lists := v.Get("lists")
	if lists.IsUndefined() || lists.IsNull() {
		return material, nil
	}

	// Object.keys(lists) is the only way to enumerate a plain object from Go.
	keys := js.Global().Get("Object").Call("keys", lists)
	for i := range keys.Length() {
		territory := keys.Index(i).String()

		data, err := toBytes(lists.Get(territory))
		if err != nil {
			return nil, fmt.Errorf("trust.lists[%s]: %w", territory, err)
		}

		material.Lists[territory] = data
	}

	return material, nil
}

// toBytes copies a Uint8Array or ArrayBuffer into Go memory.
func toBytes(v js.Value) ([]byte, error) {
	if v.IsUndefined() || v.IsNull() {
		return nil, nil
	}

	if v.InstanceOf(js.Global().Get("ArrayBuffer")) {
		v = js.Global().Get("Uint8Array").New(v)
	}

	if !v.InstanceOf(js.Global().Get("Uint8Array")) {
		return nil, fmt.Errorf("expected a Uint8Array, got %s", v.Type())
	}

	out := make([]byte, v.Length())
	js.CopyBytesToGo(out, v)

	return out, nil
}

// promise runs work on a goroutine and resolves a JavaScript promise with its
// result.
func promise(work func() (any, error)) any {
	handler := js.FuncOf(func(_ js.Value, args []js.Value) any {
		resolve, reject := args[0], args[1]

		go func() {
			defer func() {
				// A panic must surface as a rejected promise rather than tearing
				// down the runtime and leaving the page with a dead module.
				if r := recover(); r != nil {
					reject.Invoke(errorValue(fmt.Sprintf("%v", r)))
				}
			}()

			value, err := work()
			if err != nil {
				reject.Invoke(errorValue(err.Error()))

				return
			}

			resolve.Invoke(value)
		}()

		return nil
	})

	return js.Global().Get("Promise").New(handler)
}

func rejected(message string) any {
	return js.Global().Get("Promise").Call("reject", errorValue(message))
}

func errorValue(message string) js.Value {
	return js.Global().Get("Error").New(message)
}
