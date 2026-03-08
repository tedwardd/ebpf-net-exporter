# ebpf-net-exporter Makefile
#
# Build requirements (build host only — targets need none of these):
#   - Go 1.22+
#   - clang 14+
#       Arch:   pacman -S clang
#       Ubuntu: apt install clang
#   - bpftool   (used once to generate bpf/vmlinux.h)
#       Arch:   pacman -S bpf
#       Ubuntu: apt install linux-tools-common linux-tools-$(uname -r)
#   - libbpf headers
#       Arch:   pacman -S libbpf
#       Ubuntu: apt install libbpf-dev
#
# Runtime requirements (target hosts):
#   - Linux kernel ≥ 5.4 with CONFIG_DEBUG_INFO_BTF=y  (Ubuntu 20.04+ default)
#   - Root / CAP_BPF + CAP_PERFMON

BINARY   := ebpf-net-exporter
BPF_SRC  := bpf/network_tracker.bpf.c
VMLINUX  := bpf/vmlinux.h
ANSIBLE  := ansible-playbook -i ansible/inventory.yml ansible/playbook.yml

.PHONY: all generate build deploy dry-run clean

all: generate build

# Generate vmlinux.h from the running kernel's BTF data, then run bpf2go to
# compile the eBPF C and produce the Go embedding stubs.
generate: $(VMLINUX)
	go generate ./...

$(VMLINUX):
	$(shell which bpftool || echo /usr/bin/bpftool) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Build the Go binary.  Requires that `generate` has been run at least once.
build:
	CGO_ENABLED=0 go build -o $(BINARY) .

# Deploy to all hosts in ansible/inventory.yml (prompts for sudo password).
deploy: build
	$(ANSIBLE) -K

# Preview what deploy would change without making any changes.
dry-run: build
	$(ANSIBLE) -K --check --diff

clean:
	rm -f $(BINARY) $(VMLINUX)
	rm -f networktracker_*.go networktracker_*.o
