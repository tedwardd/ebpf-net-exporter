package main

import (
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	protoTCP uint8 = 6
	protoUDP uint8 = 17
	dirRX    uint8 = 0
	dirTX    uint8 = 1
)

var bytesDesc = prometheus.NewDesc(
	"process_network_bytes_total",
	"Cumulative bytes transferred by process over the network since exporter start.",
	[]string{"comm", "interface", "proto", "direction"},
	nil,
)

// Collector reads the BPF PERCPU_HASH map on every Prometheus scrape and
// exposes per-(comm, interface, proto, direction) byte counters.
type Collector struct {
	m *ebpf.Map
}

func NewCollector(m *ebpf.Map) *Collector {
	return &Collector{m: m}
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- bytesDesc
}

// Collect reads the BPF map directly on each scrape.  The map is a
// PERCPU_HASH, so each key has one value slot per possible CPU; we sum them
// to get a host-wide total.  Values are cumulative counters, which map
// naturally to the Prometheus counter type — Prometheus computes rate()
// over them without any in-process delta logic.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	var key NetworkTrackerNetKeyT
	var perCPU []uint64

	iter := c.m.Iterate()
	for iter.Next(&key, &perCPU) {
		var total uint64
		for _, v := range perCPU {
			total += v
		}
		if total == 0 {
			continue
		}

		ch <- prometheus.MustNewConstMetric(
			bytesDesc,
			prometheus.CounterValue,
			float64(total),
			commString(key.Comm),
			ifaceName(key.Ifindex),
			protoLabel(key.Proto),
			dirLabel(key.Direction),
		)
	}

	if err := iter.Err(); err != nil {
		log.Printf("BPF map iteration error: %v", err)
	}
}

// commString converts a null-terminated int8 array (kernel comm field) to a
// Go string.
func commString(comm [16]int8) string {
	b := make([]byte, 0, 16)
	for _, c := range comm {
		if c == 0 {
			break
		}
		b = append(b, byte(c))
	}
	return string(b)
}

// ifaceName resolves a kernel interface index to a human-readable name.
// ifindex 0 means the socket was not bound to a specific interface, which is
// the common case for servers with a single default route — labelled "any".
func ifaceName(ifindex uint32) string {
	if ifindex == 0 {
		return "any"
	}
	iface, err := net.InterfaceByIndex(int(ifindex))
	if err != nil {
		// Interface may have been removed since the packet was recorded.
		return fmt.Sprintf("if%d", ifindex)
	}
	return iface.Name
}

func protoLabel(proto uint8) string {
	switch proto {
	case protoTCP:
		return "tcp"
	case protoUDP:
		return "udp"
	default:
		return fmt.Sprintf("proto%d", proto)
	}
}

func dirLabel(dir uint8) string {
	if dir == dirRX {
		return "rx"
	}
	return "tx"
}
