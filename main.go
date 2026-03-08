package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// BPF stubs are generated via `make generate`, which detects the native arch
// and calls bpf2go accordingly.  See the Makefile for details.

// version is overridden at build time via -ldflags "-X main.version=<tag>".
var version = "dev"

func main() {
	addr := flag.String("addr", ":9102", "address to listen on")
	versionFlag := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *versionFlag {
		fmt.Println(version)
		return
	}

	// Needed on kernels < 5.11 to allow locking memory for BPF maps.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("removing memlock limit: %v", err)
	}

	objs := NetworkTrackerObjects{}
	if err := LoadNetworkTrackerObjects(&objs, nil); err != nil {
		log.Fatalf("loading BPF objects: %v", err)
	}
	defer objs.Close()

	links, err := attachProbes(&objs)
	if err != nil {
		log.Fatalf("attaching kprobes: %v", err)
	}
	defer closeLinks(links)

	prometheus.MustRegister(NewCollector(objs.NetStats))

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := &http.Server{Addr: *addr, Handler: mux}

	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		<-ch
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("HTTP shutdown: %v", err)
		}
	}()

	log.Printf("ebpf-net-exporter listening on %s", *addr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("HTTP server: %v", err)
	}
}

// attachProbes attaches all kprobes and kretprobes.  Optional probes (those
// that may not exist on all kernels) are attached on a best-effort basis and
// their absence is only logged.
func attachProbes(objs *NetworkTrackerObjects) ([]link.Link, error) {
	var links []link.Link

	kprobe := func(symbol string, prog *ebpf.Program) error {
		l, err := link.Kprobe(symbol, prog, nil)
		if err != nil {
			return err
		}
		links = append(links, l)
		return nil
	}

	kretprobe := func(symbol string, prog *ebpf.Program) error {
		l, err := link.Kretprobe(symbol, prog, nil)
		if err != nil {
			return err
		}
		links = append(links, l)
		return nil
	}

	// Required probes — fatal if unavailable.
	required := []func() error{
		func() error { return kprobe("tcp_sendmsg", objs.KprobeTcpSendmsg) },
		func() error { return kprobe("tcp_cleanup_rbuf", objs.KprobeTcpCleanupRbuf) },
		func() error { return kprobe("udp_sendmsg", objs.KprobeUdpSendmsg) },
		func() error { return kprobe("udp_recvmsg", objs.KprobeUdpRecvmsg) },
		func() error { return kretprobe("udp_recvmsg", objs.KretprobeUdpRecvmsg) },
	}
	for _, fn := range required {
		if err := fn(); err != nil {
			closeLinks(links)
			return nil, err
		}
	}

	// Optional — attached if the kernel symbol exists.
	if err := kprobe("udpv6_sendmsg", objs.KprobeUdpv6Sendmsg); err != nil {
		log.Printf("optional probe udpv6_sendmsg not attached: %v", err)
	}

	return links, nil
}

func closeLinks(links []link.Link) {
	for _, l := range links {
		l.Close()
	}
}
