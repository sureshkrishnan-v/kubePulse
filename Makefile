# KubePulse Makefile
# Targets: generate (BPF → Go bindings), build, test, clean

BINARY  := bin/kubepulse
CMD     := ./cmd/kubepulse
PROBES  := ./internal/probes/...

# Build flags
LDFLAGS := -s -w -X main.version=$(shell git describe --tags --always 2>/dev/null || echo "dev")

.PHONY: all generate build test clean

all: generate build

# Generate BPF Go bindings for all probes.
# Each probe package has its own //go:generate directive.
# Adding a new probe = create the package, no Makefile edits needed.
generate:
	@echo "==> Generating BPF Go bindings..."
	go generate $(PROBES)
	@echo "==> Done"

# Build the kubepulse binary
build:
	@echo "==> Building kubepulse..."
	go build -v -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD)
	@echo "==> Built $(BINARY)"

# Run Go unit tests
test:
	go test -v -race ./internal/...

# Clean build artifacts and generated files
clean:
	rm -f $(BINARY)
	find internal/probes -name 'bpf_*.go' -delete
	find internal/probes -name 'bpf_*.o' -delete
