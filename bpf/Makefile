CLANG ?= clang
CC ?= cc
BPFTOOL ?= bpftool

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
CFLAGS := -O2 -g -Wall
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
LIBS := -lbpf -lelf -lz -lsqlite3

DB_SRCS     := $(wildcard ../db/*.c)
ENGINE_SRCS := $(wildcard ../engine/*.c) $(wildcard ../engine/rules/*.c)

all: vmlinux.h sensor.skel.h agent

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@
	
sensor.bpf.o: sensor.bpf.c include/event_schema.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -I. -Iinclude -c $< -o $@

sensor.skel.h: sensor.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

agent: loader.c sensor.skel.h include/event_schema.h $(DB_SRCS) $(ENGINE_SRCS)
	$(CC) $(CFLAGS) -I. -Iinclude -I.. loader.c $(DB_SRCS) $(ENGINE_SRCS) -o $@ $(LIBS)

clean:
	rm -f *.o *.skel.h vmlinux.h agent