package tcp

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror" -target amd64 bpf ../../../bpf/tcp_tracer.c -- -I../../../bpf
