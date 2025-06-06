# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT := output
CLANG ?= clang
BPFTOOL ?= bpftool
INCLUDES := -I$(OUTPUT) -I../src/include/
CFLAGS := -g -Wall -D_GNU_SOURCE
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS) -L../src/ -luring -lbpf

APPS = link

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.

CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

.PHONY: all clean
all: $(APPS)

clean:
	$(Q)rm -rf $(OUTPUT) $(APPS)

# Build BPF code
$(OUTPUT)/%.bpf.o: %.bpf.c $(wildcard %.h)
	mkdir -p ${OUTPUT}
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)		      \
		     $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES)		      \
		     -c $(filter %.c,$^) -o $(patsubst %.bpf.o,%.tmp.bpf.o,$@)
	$(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp.bpf.o,$@)

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# Build user-space code
$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

$(OUTPUT)/%.o: %.c $(wildcard %.h)
	$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# Build application binary
$(APPS): %: $(OUTPUT)/%.o
	$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -o $@

# delete failed targets
.DELETE_ON_ERROR:
# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:

