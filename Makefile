CURDIR := $(abspath .)
BPFDIR := $(CURDIR)/bpf
DPPROG := $(BPFDIR)/datapath
GOBPFDIR := $(CURDIR)/internal/bpf

BPFTOOL := bpftool
CLANG := clang
GO := go
RM := rm

## check if the vmlinux exists in /sys/kernel/btf directory
VMLINUX_BTF ?= $(wildcard /sys/kernel/btf/vmlinux)
ifeq ($(VMLINUX_BTF),)
$(error Cannot find a vmlinux)
endif

LDFLAGS := -ldflags="-s -w" -buildvcs=false 
bin/liteb4d: $(GO_SOURCES) vmlinux build-bpf
	@$(GO) build $(LDFLAGS) -o $@ ./cmd/liteb4d

.PHONY: vmlinux
vmlinux: $(BPFDIR)/vmlinux.h

.PHONY: build-bpf
build-bpf:
	@$(GO) generate $(GOBPFDIR)/generator.go

$(BPFDIR)/vmlinux.h:
	@$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@

.PHONY: clean
clean:
	-@$(RM) -f $(BPFDIR)/vmlinux.h
	-@$(RM) -f $(GOBPFDIR)/*.o
	-@$(RM) -f $(GOBPFDIR)/datapath_bpf*.go
