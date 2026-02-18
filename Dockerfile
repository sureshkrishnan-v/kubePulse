# Multi-stage Dockerfile for KubePulse
# Stage 1: Build BPF programs and Go binary
# Stage 2: Minimal distroless runtime image

# ========== Builder Stage ==========
FROM golang:1.22-bookworm AS builder

# Install BPF build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libelf-dev \
    libbpf-dev \
    linux-headers-generic \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy Go module files first for layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Generate BPF Go bindings and build the binary
RUN make generate && make build

# ========== Runtime Stage ==========
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="KubePulse"
LABEL org.opencontainers.image.description="eBPF-powered Kubernetes-aware TCP latency and DNS monitoring agent"
LABEL org.opencontainers.image.source="https://github.com/sureshkrishnan-v/kubePulse"
LABEL org.opencontainers.image.version="1.0.0"

# Copy the statically compiled binary
COPY --from=builder /build/bin/kubepulse /kubepulse

# Expose metrics port
EXPOSE 9090

# Run as root (required for BPF program loading)
USER root

ENTRYPOINT ["/kubepulse"]
