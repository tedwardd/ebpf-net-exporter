# ebpf-net-exporter

A Prometheus exporter that uses eBPF kprobes to track per-process network bandwidth on Linux hosts. It exposes cumulative byte counters broken down by process name, interface, protocol, and direction — with no packet capture and negligible overhead.

## Metrics

A single counter is exposed:

```
process_network_bytes_total{comm, interface, proto, direction}
```

| Label | Values | Notes |
|---|---|---|
| `comm` | e.g. `nginx`, `sshd`, `python3` | Kernel process name, max 16 chars |
| `interface` | e.g. `eth0`, `tailscale0`, `any` | `any` for sockets not bound to a specific interface |
| `proto` | `tcp`, `udp` | |
| `direction` | `tx`, `rx` | |

### Example output

```
process_network_bytes_total{comm="nginx",interface="any",proto="tcp",direction="tx"} 1.048576e+09
process_network_bytes_total{comm="nginx",interface="any",proto="tcp",direction="rx"} 2.62144e+08
process_network_bytes_total{comm="sshd",interface="any",proto="tcp",direction="tx"} 5.12e+05
process_network_bytes_total{comm="node_exporter",interface="any",proto="tcp",direction="rx"} 8192
```

These are cumulative counters. Use `rate()` or `irate()` in Prometheus to get bytes/second:

```promql
rate(process_network_bytes_total{direction="tx"}[1m])
```

### Interface label note

The `interface` label is derived from the socket's bound interface index (`sk->sk_bound_dev_if`). Most server sockets are not explicitly bound to an interface, so they will show `interface="any"`. Processes that bind to a specific interface (e.g. certain VPN clients) will show the correct interface name.

## How it works

Six eBPF kprobes are attached to kernel functions in the TCP and UDP send/receive paths. All hooks fire in process context, so `bpf_get_current_comm()` accurately identifies the calling process.

| Hook | Tracks |
|---|---|
| `kprobe/tcp_sendmsg` | TCP bytes sent |
| `kprobe/tcp_cleanup_rbuf` | TCP bytes received (post-copy) |
| `kprobe/udp_sendmsg` | UDP bytes sent (IPv4) |
| `kprobe/udpv6_sendmsg` | UDP bytes sent (IPv6, optional) |
| `kprobe/udp_recvmsg` | Saves interface index for kretprobe |
| `kretprobe/udp_recvmsg` | UDP bytes received (return value) |

Byte counts are stored in a `BPF_MAP_TYPE_PERCPU_HASH` map keyed by `(comm, ifindex, proto, direction)`. Using per-CPU values eliminates atomic operations on the hot path. The Go process sums across CPUs on each Prometheus scrape.

The binary embeds the compiled eBPF bytecode and uses [CO-RE](https://nakryiko.com/posts/bpf-portability-and-co-re/) (Compile Once, Run Everywhere) to load on any BTF-enabled kernel without requiring kernel headers on the target host.

## Requirements

### Target hosts (runtime)

- Linux kernel ≥ 5.4 with `CONFIG_DEBUG_INFO_BTF=y`
  - Ubuntu 20.04+ — enabled by default
  - Any other distribution with a modern kernel
- Root or `CAP_BPF` + `CAP_PERFMON` (the latter two require kernel ≥ 5.8)

### Build host

Only needed if modifying the eBPF C code (`bpf/network_tracker.bpf.c`). A pre-compiled Go stub (`networktracker_x86_bpfel.go`) is committed to the repository, so `make build` works without any of these.

| Tool | Arch | Ubuntu |
|---|---|---|
| Go 1.22+ | `pacman -S go` | `snap install go` |
| clang 14+ | `pacman -S clang` | `apt install clang` |
| bpftool | `pacman -S bpf` | `apt install linux-tools-common linux-tools-$(uname -r)` |
| libbpf headers | `pacman -S libbpf` | `apt install libbpf-dev` |

## Building

```bash
# Build only (uses the committed pre-compiled eBPF stub)
make build

# Regenerate eBPF stub from C source, then build
# (required after editing bpf/network_tracker.bpf.c)
make generate
make build

# Or both in one step
make
```

## Running

```bash
sudo ./ebpf-net-exporter
# Metrics available at http://localhost:9102/metrics
# Health check at http://localhost:9102/healthz

# Custom address
sudo ./ebpf-net-exporter --addr :9200
```

## Deployment with Ansible

The `ansible/` directory contains a role that copies the binary and installs a systemd service on target hosts.

### 1. Edit the inventory

```yaml
# ansible/inventory.yml
all:
  children:
    ebpf_monitored:
      hosts:
        myserver:
          ansible_host: 192.168.1.10
          ansible_user: myuser
```

### 2. Build the binary

```bash
make build
```

### 3. Deploy

```bash
# Preview changes
make dry-run

# Apply
make deploy   # prompts for sudo password (-K)
```

The role:
- Copies the binary to `/usr/local/bin/ebpf-net-exporter`
- Installs and enables a systemd service (`ebpf-net-exporter.service`) running as root
- Restarts the service on binary or config changes

### Prometheus scrape config

```yaml
- job_name: ebpf-net-exporter
  static_configs:
    - targets:
        - myserver:9102
      labels:
        host: myserver
```

## Architecture

```
┌─────────────────────────────────────────────────────┐
│ Linux kernel                                        │
│                                                     │
│  tcp_sendmsg() ──► kprobe ──┐                       │
│  tcp_cleanup_rbuf() ─► kprobe ──┤                   │
│  udp_sendmsg() ──► kprobe ──┤   BPF_PERCPU_HASH     │
│  udpv6_sendmsg() ─► kprobe ──┤  {comm,ifindex,      │
│  udp_recvmsg() ───► kprobe ──┤   proto,dir} → bytes │
│  udp_recvmsg() ─► kretprobe─┘                       │
└───────────────────────────────┬─────────────────────┘
                                │ map read on scrape
                    ┌───────────▼────────────┐
                    │ ebpf-net-exporter      │
                    │ :9102/metrics          │
                    └───────────┬────────────┘
                                │
                    ┌───────────▼────────────┐
                    │ Prometheus             │
                    └───────────┬────────────┘
                                │
                    ┌───────────▼────────────┐
                    │ Grafana                │
                    └────────────────────────┘
```
