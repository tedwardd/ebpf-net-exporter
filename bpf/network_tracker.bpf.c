//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

#define DIR_RX 0
#define DIR_TX 1

// Map key: (comm, interface index, protocol, direction)
struct net_key_t {
	char  comm[16];
	__u32 ifindex;
	__u8  proto;
	__u8  direction;
	__u8  _pad[2];
};

// Per-CPU hash map: avoids atomic operations on the hot path.
// Userspace sums across CPUs when reading.
//
// Capacity: each unique (comm, ifindex, proto, direction) tuple occupies one
// entry.  10240 accommodates ~640 distinct processes × 2 protocols × 2
// directions × ~4 interfaces with room to spare on typical hosts.  If the map
// fills, new tuples are silently dropped (existing counters continue to
// accumulate correctly).  Increase max_entries and recompile if you see
// truncated process coverage on a very busy host.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__type(key, struct net_key_t);
	__type(value, __u64);
	__uint(max_entries, 10240);
} net_stats SEC(".maps");

// Scratch map used to pass the resolved ifindex from the udp_recvmsg kprobe
// to its kretprobe, keyed by thread ID.  We read sk->skc_bound_dev_if at
// kprobe entry (while sk is still accessible) rather than storing the raw
// pointer, since bpf2go cannot generate Go types for kernel pointer fields.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);   // tid
	__type(value, __u32); // ifindex
	__uint(max_entries, 1024);
} udp_recv_ifindex SEC(".maps");

// ── helpers ───────────────────────────────────────────────────────────────────

static __always_inline void
record(const char *comm, __u32 ifindex, __u8 proto, __u8 dir, __u64 bytes)
{
	struct net_key_t key = {};
	__builtin_memcpy(key.comm, comm, 16);
	key.ifindex   = ifindex;
	key.proto     = proto;
	key.direction = dir;

	// Lookup-or-init pattern: safe with PERCPU maps since each CPU owns
	// its own value slot — no atomic needed.
	__u64 zero = 0;
	__u64 *val = bpf_map_lookup_elem(&net_stats, &key);
	if (!val) {
		bpf_map_update_elem(&net_stats, &key, &zero, BPF_NOEXIST);
		val = bpf_map_lookup_elem(&net_stats, &key);
	}
	if (val)
		*val += bytes;
}

// ── TCP TX ────────────────────────────────────────────────────────────────────
//
// tcp_sendmsg is called in process context, so bpf_get_current_comm() is
// accurate.  The `size` argument is the application payload length.
//
// Device attribution: sk->__sk_common.skc_bound_dev_if is the ifindex of an
// explicitly bound interface, or 0 for unbound sockets (shown as "any").

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(kprobe_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
	if (size == 0)
		return 0;

	char comm[16];
	bpf_get_current_comm(comm, sizeof(comm));
	__u32 ifindex = BPF_CORE_READ(sk, __sk_common.skc_bound_dev_if);
	record(comm, ifindex, IPPROTO_TCP, DIR_TX, size);
	return 0;
}

// ── TCP RX ────────────────────────────────────────────────────────────────────
//
// tcp_cleanup_rbuf is called when the process has consumed data from the
// receive buffer — it is in process context and `copied` is the actual
// number of bytes handed to the application.

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(kprobe_tcp_cleanup_rbuf, struct sock *sk, int copied)
{
	if (copied <= 0)
		return 0;

	char comm[16];
	bpf_get_current_comm(comm, sizeof(comm));
	__u32 ifindex = BPF_CORE_READ(sk, __sk_common.skc_bound_dev_if);
	record(comm, ifindex, IPPROTO_TCP, DIR_RX, (__u64)copied);
	return 0;
}

// ── UDP TX (IPv4) ─────────────────────────────────────────────────────────────

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(kprobe_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
	if (len == 0)
		return 0;

	char comm[16];
	bpf_get_current_comm(comm, sizeof(comm));
	__u32 ifindex = BPF_CORE_READ(sk, __sk_common.skc_bound_dev_if);
	record(comm, ifindex, IPPROTO_UDP, DIR_TX, len);
	return 0;
}

// ── UDP TX (IPv6) ─────────────────────────────────────────────────────────────
//
// IPv6 UDP send goes through udpv6_sendmsg.  Attached as optional — if the
// symbol is absent (e.g. kernel compiled without IPv6) attachment is skipped.

SEC("kprobe/udpv6_sendmsg")
int BPF_KPROBE(kprobe_udpv6_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
	if (len == 0)
		return 0;

	char comm[16];
	bpf_get_current_comm(comm, sizeof(comm));
	__u32 ifindex = BPF_CORE_READ(sk, __sk_common.skc_bound_dev_if);
	record(comm, ifindex, IPPROTO_UDP, DIR_TX, len);
	return 0;
}

// ── UDP RX (kprobe + kretprobe pair) ─────────────────────────────────────────
//
// udp_recvmsg is in process context. The return value is the number of bytes
// received, so we use a kprobe to save the sock pointer and a kretprobe to
// record the actual byte count.

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(kprobe_udp_recvmsg, struct sock *sk)
{
	__u32 tid     = (__u32)bpf_get_current_pid_tgid();
	__u32 ifindex = BPF_CORE_READ(sk, __sk_common.skc_bound_dev_if);
	bpf_map_update_elem(&udp_recv_ifindex, &tid, &ifindex, BPF_ANY);
	return 0;
}

SEC("kretprobe/udp_recvmsg")
int BPF_KRETPROBE(kretprobe_udp_recvmsg, int ret)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();

	if (ret <= 0) {
		bpf_map_delete_elem(&udp_recv_ifindex, &tid);
		return 0;
	}

	__u32 *ifindex = bpf_map_lookup_elem(&udp_recv_ifindex, &tid);
	if (ifindex) {
		char comm[16];
		bpf_get_current_comm(comm, sizeof(comm));
		record(comm, *ifindex, IPPROTO_UDP, DIR_RX, (__u64)ret);
		bpf_map_delete_elem(&udp_recv_ifindex, &tid);
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
