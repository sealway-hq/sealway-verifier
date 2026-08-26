GO             ?= go
GOLANGCI       ?= golangci-lint
MOCKERY        ?= mockery
MOCKERY_VERSION ?= v3.7.3
BIN            ?= bin/sealway-verifier
WEB_OUT        ?= dist/web
NPM_PKG        ?= apps/wasm/npm
WEB_PORT       ?= 8080
FUZZTIME     ?= 30s
FUZZ_TARGETS := FuzzManifestParse FuzzHashUnmarshal FuzzMerkleProofVerify \
                FuzzTimestampParse FuzzBundleOpen FuzzVerifyBundle FuzzVerifyCertificate
RELEASE_TARGETS := darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64

.PHONY: all
all: lint test build

.PHONY: build
build:
	CGO_ENABLED=0 $(GO) build -o $(BIN) ./apps/sealway-verifier

.PHONY: test
test:
	$(GO) test ./...

.PHONY: race
race:
	$(GO) test -race ./...

.PHONY: cover
cover:
	$(GO) test -coverpkg=./packages/...,./apps/... -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -1

.PHONY: cover-html
cover-html: cover
	$(GO) tool cover -html=coverage.out -o coverage.html

.PHONY: fuzz
fuzz:
	@for target in $(FUZZ_TARGETS); do \
		echo "==> $$target"; \
		$(GO) test ./packages/verifier/ -run '^$$' -fuzz "^$$target$$" -fuzztime $(FUZZTIME) || exit 1; \
	done
	@echo "==> FuzzVerify (XML signatures)"
	@$(GO) test ./packages/verifier/trustlist/xmldsig/ -run '^$$' -fuzz '^FuzzVerify$$' \
		-fuzztime $(FUZZTIME)

# Run the anchor checks against the live public networks. Excluded from the
# ordinary test run so that no build depends on third party availability.
.PHONY: test-live
test-live:
	SEALWAY_VERIFIER_LIVE_TESTS=1 $(GO) test ./tests/e2e/ -run Live -v

.PHONY: lint
lint:
	$(GOLANGCI) run ./...

.PHONY: fmt
fmt:
	$(GOLANGCI) fmt ./...

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: tidy
tidy:
	$(GO) mod tidy

# Regenerate the test mocks. The generated files are committed so that the test
# suite builds without the generator installed.
.PHONY: mocks
mocks:
	$(GO) run github.com/vektra/mockery/v3@$(MOCKERY_VERSION)

# Fail when the committed mocks no longer match the interfaces they mock.
.PHONY: mocks-check
mocks-check: mocks
	@git diff --exit-code -- internal/mocks \
		|| (echo "generated mocks are out of date: run 'make mocks'" && exit 1)

# Check every release target builds without cgo, which is also what keeps a
# future WebAssembly build possible.
.PHONY: cross
cross:
	@for target in $(RELEASE_TARGETS); do \
		GOOS=$${target%/*} GOARCH=$${target#*/} CGO_ENABLED=0 \
			$(GO) build -o /dev/null ./apps/sealway-verifier || exit 1; \
		echo "built $$target"; \
	done
	@GOOS=js GOARCH=wasm CGO_ENABLED=0 $(GO) build ./packages/... && echo "built js/wasm"

# Exercise the browser module in the js/wasm runtime, through the JavaScript API
# a page actually calls. Needs node, which provides that runtime outside a
# browser.
.PHONY: wasm-test
wasm-test:
	GOOS=js GOARCH=wasm $(GO) test -exec "$$($(GO) env GOROOT)/lib/wasm/go_js_wasm_exec" ./apps/wasm/

# Source guarded by a js && wasm build tag is invisible to an ordinary lint run,
# so it gets its own.
.PHONY: wasm-lint
wasm-lint:
	GOOS=js GOARCH=wasm $(GOLANGCI) run ./apps/wasm/...

# Build the browser demonstration into dist/web: the WebAssembly module, the
# Go runtime shim, the static page, and the European Trusted Lists it serves
# from its own origin because the official endpoints allow no cross-origin
# request.
.PHONY: wasm
wasm:
	@mkdir -p $(WEB_OUT)/trust/lists
	GOOS=js GOARCH=wasm CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" \
		-o $(WEB_OUT)/sealway.wasm ./apps/wasm
	cp "$$($(GO) env GOROOT)/lib/wasm/wasm_exec.js" $(WEB_OUT)/wasm_exec.js
	cp apps/wasm/web/index.html apps/wasm/web/demo.js apps/wasm/web/style.css $(WEB_OUT)/
	gunzip -c testdata/trust/eu-lotl.xml.gz > $(WEB_OUT)/trust/lotl.xml
	gunzip -c testdata/trust/es-trusted-list.xml.gz > $(WEB_OUT)/trust/lists/es.xml
	@echo "built $(WEB_OUT) ($$(du -h $(WEB_OUT)/sealway.wasm | cut -f1) of WebAssembly)"

# Assemble the npm package: the module, the Go runtime shim that is version
# locked to it, and the licence. The wrapper and its types are committed; these
# three are build output.
.PHONY: npm-package
npm-package:
	GOOS=js GOARCH=wasm CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" \
		-o $(NPM_PKG)/sealway.wasm ./apps/wasm
	cp "$$($(GO) env GOROOT)/lib/wasm/wasm_exec.js" $(NPM_PKG)/wasm_exec.js
	cp LICENSE $(NPM_PKG)/LICENSE
	@echo "assembled $(NPM_PKG)"

# Serve the demonstration. A server is needed because a module cannot be
# instantiated from a file:// origin.
.PHONY: wasm-serve
wasm-serve: wasm
	@echo "http://localhost:$(WEB_PORT)"
	@cd $(WEB_OUT) && python3 -m http.server $(WEB_PORT)

.PHONY: clean
clean:
	rm -rf bin dist coverage.out coverage.html
