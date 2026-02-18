# KubePulse Makefile
# eBPF-powered Kubernetes-aware TCP latency and DNS monitoring agent

BINARY_NAME := kubepulse
BUILD_DIR := bin
CMD_DIR := cmd/kubepulse
BPF_DIR := bpf
LOADER_DIR := internal/loader

# Build flags
GO := go
GOFLAGS := -v
LDFLAGS := -s -w -X main.version=0.1.0

# BPF compilation flags
CLANG := clang
BPF2GO := $(GO) run github.com/cilium/ebpf/cmd/bpf2go
BPF_CFLAGS := -O2 -g -Wall -Werror
BPF_TARGET := amd64

.PHONY: all generate build clean test lint run

all: generate build

# Generate Go bindings from BPF C programs using bpf2go
generate:
	@echo "==> Generating BPF Go bindings..."
	cd $(LOADER_DIR) && GOPACKAGE=loader $(BPF2GO) \
		-cc $(CLANG) \
		-cflags "$(BPF_CFLAGS)" \
		-target $(BPF_TARGET) \
		tcpTracer ../../$(BPF_DIR)/tcp_tracer.c -- -I../../$(BPF_DIR)
	cd $(LOADER_DIR) && GOPACKAGE=loader $(BPF2GO) \
		-cc $(CLANG) \
		-cflags "$(BPF_CFLAGS)" \
		-target $(BPF_TARGET) \
		dnsTracer ../../$(BPF_DIR)/dns_tracer.c -- -I../../$(BPF_DIR)
	@echo "==> BPF Go bindings generated"

# Build the kubepulse binary
build:
	@echo "==> Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) ./$(CMD_DIR)
	@echo "==> Built $(BUILD_DIR)/$(BINARY_NAME)"

# Clean build artifacts
clean:
	@echo "==> Cleaning..."
	rm -rf $(BUILD_DIR)
	rm -f $(LOADER_DIR)/tcptracer_bpfel_*.go
	rm -f $(LOADER_DIR)/tcptracer_bpfel_*.o
	@echo "==> Clean complete"

# Run tests
test:
	$(GO) test -v -race ./...

# Run linter
lint:
	golangci-lint run ./...

# Run kubepulse (requires root)
run: build
	sudo $(BUILD_DIR)/$(BINARY_NAME)

# Docker build
docker-build:
	docker build -t kubepulse:latest .

# Show help
help:
	@echo "KubePulse Makefile targets:"
	@echo "  generate  - Generate BPF Go bindings from C sources"
	@echo "  build     - Build the kubepulse binary"
	@echo "  clean     - Remove build artifacts"
	@echo "  test      - Run all tests"
	@echo "  lint      - Run golangci-lint"
	@echo "  run       - Build and run kubepulse (requires root)"
	@echo "  all       - Generate + build (default)"
