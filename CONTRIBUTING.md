# Contributing to ebpf-net-exporter

Thank you for your interest in contributing. This document covers how to set up a development environment, make changes, and submit them.

## Repository layout

```
bpf/network_tracker.bpf.c   eBPF C source (kernel side)
collector.go                 Prometheus collector (reads BPF map, emits metrics)
main.go                      HTTP server, BPF loader, kprobe attachment
collector_test.go            Unit tests for pure Go helpers
networktracker_*_bpfel.*     Generated from the C source — do not edit by hand
Makefile                     Build targets: generate, build, deploy, clean
ansible/                     Ansible role for deploying to target hosts
.github/workflows/           CI/CD: builds for amd64 + arm64, creates releases
```

## Development environment

### Go changes only

If you are only modifying Go code (`main.go`, `collector.go`), you only need Go:

```
Go 1.22+
```

Pre-compiled BPF stubs (`networktracker_*_bpfel.go` / `.o`) are committed to the
repository, so `make build` works without any eBPF toolchain.

```bash
make build
go test ./...
```

### eBPF C changes

If you are modifying `bpf/network_tracker.bpf.c`, you also need:

| Tool | Arch Linux | Ubuntu |
|------|-----------|--------|
| clang 14+ | `pacman -S clang` | `apt install clang llvm` |
| bpftool | `pacman -S bpf` | download from [libbpf/bpftool releases](https://github.com/libbpf/bpftool/releases) |
| libbpf headers | `pacman -S libbpf` | `apt install libbpf-dev` |

Then regenerate the Go stubs and rebuild:

```bash
make generate   # regenerates bpf/vmlinux.h and networktracker_*_bpfel.*
make build
```

Commit the regenerated stubs alongside your C changes so that Go-only contributors
can still build without the eBPF toolchain.

## Making changes

1. **Fork** the repository and create a branch for your change.

2. **Test** your changes:
   ```bash
   go test ./...          # unit tests (no kernel required)
   sudo ./ebpf-net-exporter   # smoke test against a live kernel
   curl -s localhost:9102/metrics | grep process_network_bytes
   ```

3. **Keep commits focused.** One logical change per commit makes review easier
   and history more useful.

4. **Run the exporter** under realistic load if your change touches the BPF map
   read path or metric labels. Generate some traffic (`curl`, `scp`, etc.) and
   verify the output looks correct.

## Submitting a pull request

- Open a PR against `main`.
- Describe **what** the change does and **why** — include the problem it solves
  or the use case it enables.
- If you changed the BPF C code, confirm which kernel version(s) you tested on.
- CI builds for both amd64 and arm64. If you can only test one architecture,
  say so in the PR description.

## What good contributions look like

- **Bug fixes** with a description of the incorrect behaviour and how to reproduce it.
- **New protocol hooks** (e.g. QUIC, SCTP) following the existing kprobe pattern.
- **Additional labels** (e.g. cgroup, PID) — note that wider keys increase map
  pressure; see the `max_entries` comment in `bpf/network_tracker.bpf.c`.
- **Ansible role improvements** for broader distribution support.
- **Tests** for any new Go helper functions.

## Code style

- Go: standard `gofmt` formatting; idiomatic error handling (`if err != nil`).
- eBPF C: follow the style of the existing code — `__always_inline` helpers,
  `BPF_CORE_READ` for kernel struct access, `SEC("kprobe/...")` annotations.
- Avoid adding dependencies unless strictly necessary; the minimal dependency
  footprint is intentional.

## Reporting bugs

Please open a GitHub issue with:
- Kernel version (`uname -r`) and distribution
- Exporter version (`./ebpf-net-exporter -version`)
- Steps to reproduce and observed vs expected behaviour
- Relevant log output
