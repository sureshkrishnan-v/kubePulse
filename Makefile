# KubePulse Makefile
# Targets: generate, build (agent/consumer/api), test, clean, docker-up, dev-web

PROBES  := ./internal/probes/...

# Build flags
LDFLAGS := -s -w -X main.version=$(shell git describe --tags --always 2>/dev/null || echo "dev")

.PHONY: all generate build build-agent build-consumer build-api test clean docker-up docker-down dev-web

all: generate build

# Generate BPF Go bindings for all probes.
generate:
	@echo "==> Generating BPF Go bindings..."
	go generate $(PROBES)
	@echo "==> Done"

# Build all Go binaries
build: build-agent build-consumer build-api

build-agent:
	@echo "==> Building kubepulse agent..."
	go build -v -ldflags "$(LDFLAGS)" -o bin/kubepulse ./cmd/kubepulse
	@echo "==> Built bin/kubepulse"

build-consumer:
	@echo "==> Building consumer..."
	go build -v -ldflags "$(LDFLAGS)" -o bin/consumer ./cmd/consumer
	@echo "==> Built bin/consumer"

build-api:
	@echo "==> Building API server..."
	go build -v -ldflags "$(LDFLAGS)" -o bin/api ./cmd/api
	@echo "==> Built bin/api"

# Run Go unit tests
test:
	go test -v -race ./internal/...

# Infrastructure
docker-up:
	docker compose up -d

docker-down:
	docker compose down

# Frontend dev server
dev-web:
	cd web && npm run dev

# Clean
clean:
	rm -f bin/kubepulse bin/consumer bin/api
	find internal/probes -name 'bpf_*.go' -delete
	find internal/probes -name 'bpf_*.o' -delete
