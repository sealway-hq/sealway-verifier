GO             ?= go
GOLANGCI       ?= golangci-lint
MOCKERY        ?= mockery
MOCKERY_VERSION ?= v3.7.3
BIN            ?= bin/sealway-verifier
FUZZTIME     ?= 30s
FUZZ_TARGETS := FuzzManifestParse FuzzHashUnmarshal FuzzMerkleProofVerify \
                FuzzTimestampParse FuzzBundleOpen FuzzVerifyBundle FuzzVerifyCertificate
RELEASE_TARGETS := darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64

.PHONY: all
all: lint test build

.PHONY: build
build:
	CGO_ENABLED=0 $(GO) build -o $(BIN) ./apps/cli

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
			$(GO) build -o /dev/null ./apps/cli || exit 1; \
		echo "built $$target"; \
	done
	@GOOS=js GOARCH=wasm CGO_ENABLED=0 $(GO) build ./packages/... && echo "built js/wasm"

.PHONY: clean
clean:
	rm -rf bin dist coverage.out coverage.html
