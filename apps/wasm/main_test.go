// Copyright 2026 Ondarea Holding SAS. All rights reserved.
// Use of this source code is governed by the PolyForm Shield License 1.0.0
// that can be found in the LICENSE file.

//go:build js && wasm

package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"syscall/js"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests drive the module through JavaScript, in the js/wasm runtime, with
// the production proof and the real European publications. What they establish
// is that the browser build reaches the same conclusions as the command line
// one — in particular the qualified eIDAS determination, which is the whole
// reason a page carries trust material.
//
// They are built only for js/wasm and run under:
//
//	GOOS=js GOARCH=wasm go test -exec "$(go env GOROOT)/lib/wasm/go_js_wasm_exec" ./apps/wasm/

func TestMain(m *testing.M) {
	register()
	os.Exit(m.Run())
}

func TestModuleExposesItsContract(t *testing.T) {
	api := js.Global().Get("sealwayVerifier")
	require.False(t, api.IsUndefined(), "the module must publish sealwayVerifier")

	assert.Equal(t, js.TypeFunction, api.Get("verify").Type())

	// The exported version is the same value, and the same type, the report
	// carries: a front end comparing the two must not have to convert.
	assert.Equal(t, "1", api.Get("schemaVersion").String(),
		"a front end pins itself to the report schema version")
}

func TestVerifyResolvesWithTheCanonicalReport(t *testing.T) {
	value, err := await(t, verifyJS(bytesValue(productionProof(t)), map[string]any{
		"verifyAnchors": false,
		"trust":         trustMaterial(t),
	}))
	require.NoError(t, err)

	report := decode(t, value)

	assert.Equal(t, "1", report["schema_version"])
	assert.Equal(t, "SW-2026-D8DY92C8", report["certificate"].(map[string]any)["public_id"])

	statuses := statusesOf(t, report)

	// The qualified determination is the reason the page carries trust material
	// at all: it must be reached inside the browser build, from the European
	// Trusted Lists, exactly as it is on the command line.
	assert.Equal(t, "valid", statuses["timestamp.qualified"],
		"the browser build establishes qualified eIDAS status")
	assert.Equal(t, "valid", statuses["timestamp.trust_chain"])
	assert.Equal(t, "valid", statuses["timestamp.imprint"])
	assert.Equal(t, "valid", statuses["proof_merkle.root"])
	assert.Equal(t, "valid", statuses["accumulator.root"])
	assert.Equal(t, "valid", statuses["sources.availability"])

	// Nothing may be reported as failing: the production proof holds.
	for id, status := range statuses {
		assert.NotEqual(t, "invalid", status, "check %s", id)
	}
}

func TestVerifyWithoutTrustMaterialLeavesQualificationUndecided(t *testing.T) {
	value, err := await(t, verifyJS(bytesValue(productionProof(t)),
		map[string]any{"verifyAnchors": false}))
	require.NoError(t, err)

	report := decode(t, value)
	statuses := statusesOf(t, report)

	// Absent Trusted Lists the answer is unknown. Reporting it as valid would
	// claim a qualification nobody established; reporting it as invalid would
	// claim the opposite just as wrongly.
	require.Contains(t, statuses, "timestamp.qualified")
	assert.Contains(t, []string{"skipped", "indeterminate"}, statuses["timestamp.qualified"])
	assert.NotEqual(t, "complete_valid", report["result"])
}

func TestVerifyRejectsUnusableInputWithoutKillingTheModule(t *testing.T) {
	cases := map[string]js.Value{
		"not an archive":  bytesValue([]byte("this is not a zip file")),
		"empty":           bytesValue(nil),
		"a string":        js.ValueOf("a proof, honestly"),
		"a number":        js.ValueOf(42),
		"nothing at all":  js.Undefined(),
		"an empty object": js.Global().Get("Object").New(),
	}

	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := await(t, verifyJS(input, map[string]any{"verifyAnchors": false}))
			require.Error(t, err, "unusable input must reject rather than resolve")
			assert.NotEmpty(t, err.Error(), "a rejection always says what went wrong")
		})
	}

	// A page must still work after a bad file: the runtime survived and the
	// exported function is still callable.
	_, err := await(t, verifyJS(bytesValue(productionProof(t)),
		map[string]any{"verifyAnchors": false}))
	require.NoError(t, err, "the module is still usable after a rejection")
}

func TestVerifyWithNoArgumentsRejects(t *testing.T) {
	_, err := await(t, js.Global().Get("sealwayVerifier").Call("verify"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "proof")
}

func TestVerifyAcceptsAnArrayBuffer(t *testing.T) {
	// A page reading a File gets an ArrayBuffer, so accepting one directly
	// removes a conversion the caller would otherwise have to get right.
	buffer := bytesValue(productionProof(t)).Get("buffer")

	value, err := await(t, verifyJS(buffer, map[string]any{"verifyAnchors": false}))
	require.NoError(t, err)

	assert.Equal(t, "SW-2026-D8DY92C8",
		decode(t, value)["certificate"].(map[string]any)["public_id"])
}

func TestVerifyRejectsTrustMaterialItCannotRead(t *testing.T) {
	// Unreadable trust material is a caller mistake, not a verdict on the
	// proof, so it must surface as a rejection rather than as a report saying
	// the proof failed.
	_, err := await(t, verifyJS(bytesValue(productionProof(t)), map[string]any{
		"trust": map[string]any{"lotl": "a list, allegedly"},
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "trust.lotl")

	_, err = await(t, verifyJS(bytesValue(productionProof(t)), map[string]any{
		"trust": map[string]any{
			"lotl":  bytesValue([]byte("<lotl/>")),
			"lists": map[string]any{"ES": 12},
		},
	}))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "trust.lists[ES]")
}

func TestForgedTrustMaterialDoesNotProduceQualifiedStatus(t *testing.T) {
	// A page supplies the trust material, so the module must not take it on
	// trust: material that is not signed by the pinned European anchor proves
	// nothing, and must never be able to manufacture a qualified verdict.
	value, err := await(t, verifyJS(bytesValue(productionProof(t)), map[string]any{
		"verifyAnchors": false,
		"trust": map[string]any{
			"lotl":  bytesValue([]byte(`<?xml version="1.0"?><TrustServiceStatusList/>`)),
			"lists": map[string]any{"ES": bytesValue([]byte(`<?xml version="1.0"?><x/>`))},
		},
	}))
	require.NoError(t, err)

	statuses := statusesOf(t, decode(t, value))
	assert.NotEqual(t, "valid", statuses["timestamp.qualified"])
}

func TestBuildOptionsDefaultsToOffline(t *testing.T) {
	// Nothing may reach the network unless the host asked for it: a page that
	// silently contacts third parties is not what "verified in your browser"
	// promises.
	for name, v := range map[string]js.Value{
		"no options":    js.Undefined(),
		"null options":  js.Null(),
		"empty options": js.ValueOf(map[string]any{}),
		"anchors off":   js.ValueOf(map[string]any{"verifyAnchors": false}),
	} {
		t.Run(name, func(t *testing.T) {
			opts, err := buildOptions(v)
			require.NoError(t, err)
			assert.NotEmpty(t, opts, "the offline option is always applied")
		})
	}
}

func TestToMaterialReadsEveryTerritory(t *testing.T) {
	material, err := toMaterial(js.ValueOf(map[string]any{
		"lotl": bytesValue([]byte("<lotl/>")),
		"lists": map[string]any{
			"ES": bytesValue([]byte("<es/>")),
			"FR": bytesValue([]byte("<fr/>")),
		},
	}))
	require.NoError(t, err)
	require.NotNil(t, material)

	assert.Equal(t, []byte("<lotl/>"), material.LOTL)
	assert.Equal(t, []byte("<es/>"), material.Lists["ES"])
	assert.Equal(t, []byte("<fr/>"), material.Lists["FR"])
}

func TestToMaterialWithoutAListOfListsIsNoMaterial(t *testing.T) {
	// A caller that passes nothing usable must end up with no trust material at
	// all, so that qualification stays undecided rather than being attempted
	// against an empty list and reported as a failure.
	for name, v := range map[string]js.Value{
		"undefined":  js.Undefined(),
		"null":       js.Null(),
		"no lotl":    js.ValueOf(map[string]any{}),
		"empty lotl": js.ValueOf(map[string]any{"lotl": bytesValue(nil)}),
	} {
		t.Run(name, func(t *testing.T) {
			material, err := toMaterial(v)
			require.NoError(t, err)
			assert.Nil(t, material)
		})
	}
}

// verifyJS invokes the exported verify the way a page does.
func verifyJS(proof js.Value, options map[string]any) js.Value {
	return js.Global().Get("sealwayVerifier").Call("verify", proof, js.ValueOf(options))
}

func decode(t *testing.T, value js.Value) map[string]any {
	t.Helper()

	require.Equal(t, js.TypeString, value.Type(), "verify resolves with JSON text")

	var report map[string]any
	require.NoError(t, json.Unmarshal([]byte(value.String()), &report),
		"the resolved value is the canonical report as JSON")

	return report
}

func statusesOf(t *testing.T, report map[string]any) map[string]string {
	t.Helper()

	statuses := map[string]string{}

	sections, ok := report["sections"].([]any)
	require.True(t, ok, "the report always carries its sections")

	for _, section := range sections {
		checks, _ := section.(map[string]any)["checks"].([]any)
		for _, check := range checks {
			c := check.(map[string]any)
			statuses[c["id"].(string)] = c["status"].(string)
		}
	}

	require.NotEmpty(t, statuses)

	return statuses
}

// productionProof reads the real proof bundle the end to end suite uses.
func productionProof(t *testing.T) []byte {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "..", "testdata",
		"sealway-proof-SW-2026-D8DY92C8.zip"))
	require.NoError(t, err)

	return data
}

// trustMaterial reads the real European publications the demonstration page
// serves, in the shape the page hands them over.
func trustMaterial(t *testing.T) map[string]any {
	t.Helper()

	return map[string]any{
		"lotl":  bytesValue(gunzip(t, filepath.Join("..", "..", "testdata", "trust", "eu-lotl.xml.gz"))),
		"lists": map[string]any{"ES": bytesValue(gunzip(t, filepath.Join("..", "..", "testdata", "trust", "es-trusted-list.xml.gz")))},
	}
}

func gunzip(t *testing.T, path string) []byte {
	t.Helper()

	compressed, err := os.ReadFile(path)
	require.NoError(t, err)

	zr, err := gzip.NewReader(bytes.NewReader(compressed))
	require.NoError(t, err)

	data, err := io.ReadAll(zr)
	require.NoError(t, err)

	return data
}

// bytesValue copies Go bytes into a JavaScript Uint8Array.
func bytesValue(data []byte) js.Value {
	array := js.Global().Get("Uint8Array").New(len(data))
	js.CopyBytesToJS(array, data)

	return array
}

// await blocks on a JavaScript promise and reports how it settled.
func await(t *testing.T, p js.Value) (js.Value, error) {
	t.Helper()

	require.Equal(t, "Promise", p.Get("constructor").Get("name").String(),
		"verify always returns a promise, even when it fails immediately")

	type outcome struct {
		value js.Value
		err   error
	}

	done := make(chan outcome, 1)

	onResolve := js.FuncOf(func(_ js.Value, args []js.Value) any {
		done <- outcome{value: args[0]}

		return nil
	})
	defer onResolve.Release()

	onReject := js.FuncOf(func(_ js.Value, args []js.Value) any {
		done <- outcome{err: jsError(args[0])}

		return nil
	})
	defer onReject.Release()

	p.Call("then", onResolve, onReject)

	select {
	case o := <-done:
		return o.value, o.err
	case <-time.After(2 * time.Minute):
		t.Fatal("the promise never settled")

		return js.Undefined(), nil
	}
}

type jsErr string

func (e jsErr) Error() string { return string(e) }

func jsError(v js.Value) error {
	if message := v.Get("message"); !message.IsUndefined() {
		return jsErr(message.String())
	}

	return jsErr(v.String())
}
