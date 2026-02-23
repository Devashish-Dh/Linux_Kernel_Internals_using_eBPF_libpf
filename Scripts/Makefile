BPFTOOL = bpftool
CLANG   = clang
CC      = gcc
VMLINUX_H = vmlinux.h 
VMLINUX_PATH = /sys/kernel/btf/vmlinux

BPF_SRC = main.bpf.c
BPF_OBJ = main.bpf.o
USER_SRC = main.c
USER_BIN = LLT007

# Flags for userspace compilation
USER_CFLAGS = -Wall -O2
USER_LDFLAGS = -lbpf -lelf

.PHONY: all clean run

# Build both the BPF object and the userspace executable
all: $(VMLINUX_H) $(BPF_OBJ) $(USER_BIN)

# Generate vmlinux.h from the running kernel
$(VMLINUX_H):
	@if [ ! -f $(VMLINUX_PATH) ]; then \
		echo "ERROR: $(VMLINUX_PATH) not found."; \
		exit 1; \
	fi
	@echo "Generating $(VMLINUX_H) ..."
	$(BPFTOOL) btf dump file $(VMLINUX_PATH) format c > $@

# Compile BPF bytecode
$(BPF_OBJ): $(BPF_SRC) $(VMLINUX_H) eventDescriptors.h
	@echo "Compiling BPF program $< -> $@"
	$(CLANG) -O2 -g -target bpf -c $< -o $@

# Compile and link the Userspace monitor
$(USER_BIN): $(USER_SRC) eventDescriptors.h
	@echo "Compiling Userspace monitor $< -> $@"
	$(CC) $(USER_CFLAGS) $(USER_SRC) -o $@ $(USER_LDFLAGS)

# Utility to run the monitor with sudo
run: all
	sudo ./$(USER_BIN)

clean:
	rm -f $(BPF_OBJ) $(USER_BIN) $(VMLINUX_H)
