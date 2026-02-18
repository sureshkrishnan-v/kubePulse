# KubePulse Makefile
# Targets: generate (BPF → Go bindings), build, test, clean

BINARY  := bin/kubepulse
CMD     := ./cmd/kubepulse
BPF_DIR := bpf
LOADER  := internal/loader

# Build flags
LDFLAGS := -s -w -X main.version=$(shell git describe --tags --always 2>/dev/null || echo "dev")

.PHONY: all generate build test clean

all: generate build

# Generate BPF Go bindings for all probes
generate:
	@echo "==> Generating BPF Go bindings..."
	cd $(LOADER) && GOPACKAGE=loader go run github.com/cilium/ebpf/cmd/bpf2go \
		-cc clang \
		-cflags "-O2 -g -Wall -Werror" \
		-target amd64 \
		tcpTracer ../../$(BPF_DIR)/tcp_tracer.c -- -I../../$(BPF_DIR)
	cd $(LOADER) && GOPACKAGE=loader go run github.com/cilium/ebpf/cmd/bpf2go \
		-cc clang \
		-cflags "-O2 -g -Wall -Werror" \
		-target amd64 \
		dnsTracer ../../$(BPF_DIR)/dns_tracer.c -- -I../../$(BPF_DIR)
	cd $(LOADER) && GOPACKAGE=loader go run github.com/cilium/ebpf/cmd/bpf2go \
		-cc clang \
		-cflags "-O2 -g -Wall -Werror" \
		-target amd64 \
		retransmitTracer ../../$(BPF_DIR)/tcp_retransmit.c -- -I../../$(BPF_DIR)
	cd $(LOADER) && GOPACKAGE=loader go run github.com/cilium/ebpf/cmd/bpf2go \
		-cc clang \
		-cflags "-O2 -g -Wall -Werror" \
		-target amd64 \
		rstTracer ../../$(BPF_DIR)/tcp_rst.c -- -I../../$(BPF_DIR)
	cd $(LOADER) && GOPACKAGE=loader go run github.com/cilium/ebpf/cmd/bpf2go \
		-cc clang \
		-cflags "-O2 -g -Wall -Werror" \
		-target amd64 \
		oomTracer ../../$(BPF_DIR)/oomkill.c -- -I../../$(BPF_DIR)
	cd $(LOADER) && GOPACKAGE=loader go run github.com/cilium/ebpf/cmd/bpf2go \
		-cc clang \
		-cflags "-O2 -g -Wall -Werror" \
		-target amd64 \
		execTracer ../../$(BPF_DIR)/exec_tracer.c -- -I../../$(BPF_DIR)
	cd $(LOADER) && GOPACKAGE=loader go run github.com/cilium/ebpf/cmd/bpf2go \
		-cc clang \
		-cflags "-O2 -g -Wall -Werror" \
		-target amd64 \
		fileioTracer ../../$(BPF_DIR)/fileio_tracer.c -- -I../../$(BPF_DIR)
	cd $(LOADER) && GOPACKAGE=loader go run github.com/cilium/ebpf/cmd/bpf2go \
		-cc clang \
		-cflags "-O2 -g -Wall -Werror" \
		-target amd64 \
		dropTracer ../../$(BPF_DIR)/drop_tracer.c -- -I../../$(BPF_DIR)
	@echo "==> BPF Go bindings generated"

# Build the kubepulse binary
build:
	@echo "==> Building kubepulse..."
	go build -v -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD)
	@echo "==> Built $(BINARY)"

# Run Go unit tests
test:
	go test -v -race ./internal/...

# Clean build artifacts
clean:
	rm -f $(BINARY)
	rm -f $(LOADER)/tcpTracer_*.go $(LOADER)/tcpTracer_*.o
	rm -f $(LOADER)/dnsTracer_*.go $(LOADER)/dnsTracer_*.o
	rm -f $(LOADER)/retransmitTracer_*.go $(LOADER)/retransmitTracer_*.o
	rm -f $(LOADER)/rstTracer_*.go $(LOADER)/rstTracer_*.o
	rm -f $(LOADER)/oomTracer_*.go $(LOADER)/oomTracer_*.o
	rm -f $(LOADER)/execTracer_*.go $(LOADER)/execTracer_*.o
	rm -f $(LOADER)/fileioTracer_*.go $(LOADER)/fileioTracer_*.o
	rm -f $(LOADER)/dropTracer_*.go $(LOADER)/dropTracer_*.o
