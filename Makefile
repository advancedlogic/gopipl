# PIPL — build and run the server, the CLI client, and the desktop app.
#
# Two ways to run each Go program:
#   make run-*     compiles from current source every time (go run) — use
#                  this while developing, it can never be a stale binary.
#   make build     produces bin/pipl and bin/pipl-server — use these when
#                  you want a fixed artifact to launch repeatedly.
#
# A running `pipl` window locks bin/pipl.exe, so `make build` can fail to
# overwrite it. Close any open client first, or just use `make run-*`.

# Windows adds .exe; other platforms don't. Detected so paths print right.
ifeq ($(OS),Windows_NT)
EXE := .exe
else
EXE :=
endif

# Overridable knobs:
#   make run-alice PEER=./peers/alice     which peer (its keys + state)
#   make run-server ADDR=127.0.0.1:9000   listen address
#   make run-server BLOBS=./server/blobs  persist relayed ciphertext
PEER  ?= ./peers/alice
ADDR  ?= 127.0.0.1:8737
BLOBS ?= ./server/blobs
DATA  ?= ./server/directory.json

GO      := go
WAILS   := wails
BIN     := bin
DESKTOP := desktop

.DEFAULT_GOAL := help

## ---- meta ------------------------------------------------------------------

.PHONY: help
help: ## List targets
	@echo "PIPL make targets:"
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
	@echo
	@echo "Vars: PEER=$(PEER)  ADDR=$(ADDR)  BLOBS=$(BLOBS)"

## ---- build -----------------------------------------------------------------

.PHONY: build
build: ## Build bin/pipl and bin/pipl-server
	$(GO) build -o $(BIN)/ ./cmd/...
	@echo "built $(BIN)/pipl$(EXE) and $(BIN)/pipl-server$(EXE)"

.PHONY: build-desktop
build-desktop: ## Build the desktop app (Wails; frontend + Go)
	cd $(DESKTOP) && $(WAILS) build
	@echo "built $(DESKTOP)/build/bin/pipl-desktop$(EXE)"

.PHONY: build-all
build-all: build build-desktop ## Build everything

## ---- run (from source; never stale) ----------------------------------------

.PHONY: run-server
run-server: ## Run the server (ADDR=, BLOBS=, DATA= to override)
	$(GO) run ./cmd/pipl-server -addr $(ADDR) -blobs $(BLOBS) -data $(DATA)

.PHONY: run-server-mem
run-server-mem: ## Run the server memory-only (no persistence)
	$(GO) run ./cmd/pipl-server -addr $(ADDR)

.PHONY: run-server-tls
run-server-tls: ## Run the server with a stable self-signed TLS cert (pin in ./server/pin.txt)
	$(GO) run ./cmd/pipl-server -addr $(ADDR) -blobs $(BLOBS) -data $(DATA) \
		-tls-self-signed -tls-dir ./server/tls -tls-fingerprint-file ./server/pin.txt

.PHONY: run
run: ## Run the CLI/TUI as PEER (default ./peers/alice)
	$(GO) run ./cmd/pipl -home $(PEER)

# Named convenience peers for the usual three-way demo. Each is just `run`
# with a different PEER, so several terminals can chat on one machine.
.PHONY: run-alice run-bob run-carol
run-alice: ## Run the client as alice
	$(GO) run ./cmd/pipl -home ./peers/alice
run-bob: ## Run the client as bob
	$(GO) run ./cmd/pipl -home ./peers/bob
run-carol: ## Run the client as carol
	$(GO) run ./cmd/pipl -home ./peers/carol

.PHONY: run-desktop
run-desktop: ## Run the desktop app in dev mode (hot reload)
	cd $(DESKTOP) && $(WAILS) dev

## ---- verify ----------------------------------------------------------------

.PHONY: test
test: ## Run the Go test suite
	$(GO) test ./... -count=1

.PHONY: race
race: ## Run tests under the race detector
	$(GO) test ./... -count=1 -race

.PHONY: check
check: ## gofmt + vet + tests
	@test -z "$$(gofmt -l ./cmd ./internal)" || (echo "gofmt needed:"; gofmt -l ./cmd ./internal; exit 1)
	$(GO) vet ./...
	$(GO) test ./... -count=1

.PHONY: demo
demo: ## Run all three end-to-end demo scripts
	./demo.sh && ./demo-recipients.sh && ./demo-relay.sh

## ---- housekeeping ----------------------------------------------------------

.PHONY: clean
clean: ## Remove build artifacts (not peer state or server blobs)
	rm -rf $(BIN) $(DESKTOP)/build/bin
	@echo "cleaned build artifacts (peers/, server/ left intact)"

.PHONY: clean-state
clean-state: ## DANGER: also delete local peer keys and server blobs
	rm -rf $(BIN) $(DESKTOP)/build/bin ./peers ./server
	@echo "removed build artifacts, ./peers and ./server"
