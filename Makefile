#
# make
#

.PHONY: all
all: drafts-bin

.ONESHELL:
SHELL = /bin/sh

PARALLEL = $(shell $(CMD_GREP) -c ^processor /proc/cpuinfo)
MAKE = make
MAKEFLAGS += --no-print-directory

#
# tools
#

CMD_TR ?= tr
CMD_CUT ?= cut
CMD_AWK ?= awk
CMD_SED ?= sed
CMD_GIT ?= git
CMD_CLANG ?= clang
CMD_RM ?= rm
CMD_INSTALL ?= install
CMD_MKDIR ?= mkdir
CMD_TOUCH ?= touch
CMD_PKGCONFIG ?= pkg-config
CMD_GO ?= go
CMD_GREP ?= grep
CMD_CAT ?= cat
CMD_BPFTOOL = bpftool

.check_%:
#
	@command -v $* >/dev/null
	if [ $$? -ne 0 ]; then
		echo "missing required tool $*"
		exit 1
	else
		touch $@ # avoid target rebuilds due to inexistent file
	fi

#
# libs
#

LIB_ELF ?= libelf
LIB_ZLIB ?= zlib

define pkg_config
	$(CMD_PKGCONFIG) --libs $(1)
endef

.checklib_%: \
	| .check_$(CMD_PKGCONFIG)
#
	@$(CMD_PKGCONFIG) --silence-errors --validate $* 2>/dev/null
	if [ $$? -ne 0 ]; then
	        echo "missing lib $*"
		exit 1
	else
		touch $@ # avoid target rebuilds due to inexistent file
	fi

#
# tools version
#

CLANG_VERSION = $(shell $(CMD_CLANG) --version 2>/dev/null | \
	head -1 | $(CMD_TR) -d '[:alpha:]' | $(CMD_TR) -d '[:space:]' | $(CMD_CUT) -d'.' -f1)

.checkver_$(CMD_CLANG): \
	| .check_$(CMD_CLANG)
#
	@if [ ${CLANG_VERSION} -lt 12 ]; then
		echo -n "you MUST use clang 12 or newer, "
		echo "your current clang version is ${CLANG_VERSION}"
		exit 1
	fi
	touch $@ # avoid target rebuilds over and over due to inexistent file

GO_VERSION = $(shell $(CMD_GO) version 2>/dev/null | $(CMD_AWK) '{print $$3}' | $(CMD_SED) 's:go::g' | $(CMD_CUT) -d. -f1,2)
GO_VERSION_MAJ = $(shell echo $(GO_VERSION) | $(CMD_CUT) -d'.' -f1)
GO_VERSION_MIN = $(shell echo $(GO_VERSION) | $(CMD_CUT) -d'.' -f2)

.checkver_$(CMD_GO): \
	| .check_$(CMD_GO)
#
	@if [ ${GO_VERSION_MAJ} -eq 1 ]; then
		if [ ${GO_VERSION_MIN} -lt 17 ]; then
			echo -n "you MUST use golang 1.17 or newer, "
			echo "your current golang version is ${GO_VERSION}"
			exit 1
		fi
	fi
	touch $@

#
# environment
#

UNAME_M := $(shell uname -m)
UNAME_R := $(shell uname -r)

ifeq ($(UNAME_M),x86_64)
   ARCH = x86_64
   LINUX_ARCH = x86
   GO_ARCH = amd64
endif

ifeq ($(UNAME_M),aarch64)
   ARCH = arm64
   LINUX_ARCH = arm64
   GO_ARCH = arm64
endif

#
# variables
#

BTFFILE = /sys/kernel/btf/vmlinux
BPF_VCPU = v2

#
# output dir
#

OUTPUT_DIR = ./build

$(OUTPUT_DIR):
#
	@$(CMD_MKDIR) -p $@
	@$(CMD_MKDIR) -p $@/libbpf
	@$(CMD_MKDIR) -p $@/libbpf/obj

#
# local vmlinux.h
#

.PHONY: vmlinux
vmlinux: $(OUTPUT_DIR)/vmlinux.h

$(OUTPUT_DIR)/vmlinux.h: \
	| .check_$(CMD_BPFTOOL) \
	$(OUTPUT_DIR)
#
	$(CMD_BPFTOOL) btf dump file $(BTFFILE) format c > $(OUTPUT_DIR)/vmlinux.h

#
# libbpf
#

LIBBPF_CFLAGS = "-fPIC"
LIBBPF_LDLAGS =
LIBBPF_SRC = ./3rdparty/libbpf/src

.PHONY: libbpf
libbpf: $(OUTPUT_DIR)/libbpf/libbpf.a

$(OUTPUT_DIR)/libbpf/libbpf.a: \
	$(LIBBPF_SRC) \
	$(wildcard $(LIBBPF_SRC)/*.[ch]) \
	| .checkver_$(CMD_CLANG) \
	$(OUTPUT_DIR)
#
	CC="$(CMD_CLANG)" \
		CFLAGS="$(LIBBPF_CFLAGS)" \
		LD_FLAGS="$(LIBBPF_LDFLAGS)" \
		$(MAKE) \
		-C $(LIBBPF_SRC) \
		BUILD_STATIC_ONLY=1 \
		DESTDIR=$(abspath ./$(OUTPUT_DIR)/libbpf/) \
		OBJDIR=$(abspath ./$(OUTPUT_DIR)/libbpf/obj) \
		INCLUDEDIR= LIBDIR= UAPIDIR= prefix= libdir= \
		install install_uapi_headers

$(LIBBPF_SRC): \
        | .check_$(CMD_GIT)
#
ifeq ($(wildcard $@), )
	@$(CMD_GIT) submodule update --init --recursive
endif

#
# co-re ebpf
#

CORE_CFLAGS = "-fPIC"
CORE_LDLAGS =
CORE_SRC = ./drafts.bpf.c

.PHONY: bpf-core
bpf-core: $(OUTPUT_DIR)/drafts.bpf.core.o

$(OUTPUT_DIR)/drafts.bpf.core.o: \
	$(OUTPUT_DIR)/libbpf/libbpf.a \
	$(OUTPUT_DIR)/vmlinux.h \
	$(CORE_SRC) \
	| .checkver_$(CMD_CLANG) \
	$(OUTPUT_DIR)
#
	$(CMD_CLANG) \
		-O2 -g \
		-I. \
		-I$(OUTPUT_DIR) \
		-target bpf \
		-march=bpf -mcpu=$(BPF_VCPU) \
		-c $(CORE_SRC) \
		-o $@

#
# drafts
#

.PHONY: drafts
drafts: $(OUTPUT_DIR)/drafts

.PHONY: drafts-bin
drafts-bin: drafts
	@cp $(OUTPUT_DIR)/drafts ./drafts

STATIC ?= 1
GO_TAGS_EBPF =
CGO_EXT_LDFLAGS_EBPF =

ifeq ($(STATIC), 1)
    CGO_EXT_LDFLAGS_EBPF += -static
    GO_TAGS_EBPF := $(GO_TAGS_EBPF),netgo
endif

CUSTOM_CGO_CFLAGS = "-I$(abspath $(OUTPUT_DIR)/libbpf)"
CUSTOM_CGO_LDFLAGS = "$(shell $(call pkg_config, $(LIB_ELF))) $(shell $(call pkg_config, $(LIB_ZLIB))) $(abspath $(OUTPUT_DIR)/libbpf/libbpf.a)"

GO_ENV_EBPF =
GO_ENV_EBPF += GOOS=linux
GO_ENV_EBPF += CC=$(CMD_CLANG)
GO_ENV_EBPF += GOARCH=$(GO_ARCH)
GO_ENV_EBPF += CGO_CFLAGS=$(CUSTOM_CGO_CFLAGS)
GO_ENV_EBPF += CGO_LDFLAGS=$(CUSTOM_CGO_LDFLAGS)

LIBBPFGO_SRC_DIR = ./3rdparty/libbpfgo/
LIBBPFGO_SRC_FILES = $(shell find $(LIBBPFGO_SRC_DIR) -type f -name '*.go' ! -name '*_test.go')

DRAFTS_SRC_DIR = .
DRAFTS_SRC_FILES = $(shell find $(DRAFTS_SRC_DIR) -type f -name '*.go' ! -name '*_test.go')

$(OUTPUT_DIR)/drafts: \
	$(OUTPUT_DIR)/drafts.bpf.core.o \
	$(LIBBPFGO_SRC_FILES) \
	$(DRAFTS_SRC_FILES) \
	| .checkver_$(CMD_GO) \
	.checklib_$(LIB_ELF) \
	.checklib_$(LIB_ZLIB)
#
	$(GO_ENV_EBPF) $(CMD_GO) build \
		-tags $(GO_TAGS_EBPF) \
		-ldflags="-w \
			-extldflags \"$(CGO_EXT_LDFLAGS_EBPF)\" \
			-X main.version=\"$(VERSION)\" \
			" \
		-v -o $@ \
		$(DRAFTS_SRC_DIR)

#
# clean
#

.PHONY: clean
clean:
#
	$(CMD_RM) -rf ./drafts
	$(CMD_RM) -rf $(OUTPUT_DIR)
	$(CMD_RM) -f .check*
