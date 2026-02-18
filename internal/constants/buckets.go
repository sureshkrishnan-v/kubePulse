package constants

// ─── Histogram Buckets ─────────────────────────────────────────────
// Pre-defined bucket sets for Prometheus histograms.
// Changing these affects all histograms using them.

// NetworkLatencyBuckets covers 100µs to 5s — tuned for TCP/DNS latencies.
var NetworkLatencyBuckets = []float64{
	0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005,
	0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
}

// IOLatencyBuckets covers 1ms to 10s — tuned for file/disk I/O.
var IOLatencyBuckets = []float64{
	0.001, 0.005, 0.01, 0.025, 0.05, 0.1,
	0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
}

// ─── Drop Reasons ──────────────────────────────────────────────────
// Kernel SKB drop reason codes mapped to human-readable strings.

// DropReasons maps kernel drop reason codes to descriptive names.
var DropReasons = map[uint32]string{
	2:  "NOT_SPECIFIED",
	3:  "NO_SOCKET",
	4:  "PKT_TOO_SMALL",
	5:  "TCP_CSUM",
	6:  "SOCKET_FILTER",
	7:  "UDP_CSUM",
	16: "NETFILTER_DROP",
	17: "OTHERHOST",
	27: "QUEUE_PURGE",
}

// ─── Common Prometheus Label Sets ──────────────────────────────────
// Pre-defined label slices to avoid repeated allocations.

var LabelsNamespacePodNode = []string{LabelNamespace, LabelPod, LabelNode}
var LabelsNamespacePodDomainNode = []string{LabelNamespace, LabelPod, LabelDomain, LabelNode}
var LabelsNamespacePodOpNode = []string{LabelNamespace, LabelPod, LabelOp, LabelNode}
var LabelsReasonNode = []string{LabelReason, LabelNode}
var LabelsModule = []string{LabelModule}
var LabelsSubscriber = []string{LabelSubscriber}
