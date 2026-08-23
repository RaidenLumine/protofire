# File: Makefile
# Purpose: Top-level build, test, and QEMU automation entrypoints for the kernel.

.DEFAULT_GOAL := help

CARGO ?= cargo
CARGO_FLAGS ?= --offline
CRATE ?= protofire
PROFILE ?= debug
TARGET_DIR ?= target
TARGET ?= x86_64-unknown-none

ifeq ($(PROFILE),release)
CARGO_PROFILE_FLAG := --release
else ifeq ($(PROFILE),debug)
CARGO_PROFILE_FLAG :=
else
$(error PROFILE must be either debug or release)
endif

.PHONY: help doctor fmt fmt-check test test-lib test-fast test-concurrency test-storage verify verify-p0 verify-p1 verify-p2 verify-p3 check check-host check-target check-aarch64 check-riscv64 check-aarch64-runtime build build-aarch64 build-riscv64 clippy run run-aarch64 run-riscv64 clean setup-dev

help:
	@printf '%s\n' \
		'Available targets:' \
		'  make doctor         - check whether the local toolchain is ready' \
		'  make verify         - run the default P2 verification gate (override with VERIFY_TIER=p0..p3)' \
		'  make verify-p0      - format check + host/x86_64/aarch64 build checks + header coverage' \
		'  make verify-p1      - P0 plus fast concurrency/path/I-O/ABI regressions' \
		'  make verify-p2      - P1 plus storage/recovery/fault-matrix regressions' \
		'  make verify-p3      - P2 plus clippy and optional AArch64 runtime smoke' \
		'  make check          - run both host and bare-metal type checks' \
		'  make check-aarch64  - run bare-metal type checks for aarch64-unknown-none' \
		'  make check-riscv64  - run bare-metal type checks for riscv64gc-unknown-none-elf' \
		'  make check-aarch64-runtime - run the headless QEMU virt aarch64 fault/wait smoke check' \
		'  make test           - run host-side unit and integration tests' \
		'  make test-lib       - run library unit tests only' \
		'  make test-fast      - run path/I-O/syscall/user integration regressions' \
		'  make test-concurrency - run scheduler/input/condvar concurrency regressions' \
		'  make test-storage   - run filesystem/recovery/fault-injection regressions' \
		'  make fmt            - format the source tree' \
		'  make fmt-check      - verify formatting without modifying files' \
		'  make build          - build the bare-metal kernel ELF (PROFILE=debug|release)' \
		'  make build-aarch64  - build the aarch64 bare-metal kernel ELF for QEMU virt' \
		'  make build-riscv64  - build the riscv64 bare-metal kernel ELF for QEMU virt' \
		'  make clippy         - run clippy for all targets' \
		'  make run             - boot the x86_64 kernel directly on QEMU q35' \
		'  make run-aarch64    - boot the aarch64 kernel directly on QEMU virt' \
		'  make run-riscv64    - boot the riscv64 kernel directly on QEMU virt' \
		'  make clean          - remove Cargo artifacts' \
		'  make setup-dev      - no-op (runtime and demo crates are co-located in-repo)' \
		'  (disk image and ISO targets are not implemented yet)'

doctor:
	sh ./scripts/doctor.sh

# The co-located runtime and demo crates live inside the kernel crate
# (src/user/shared/, src/user/demo/).  No symlinks needed.
setup-dev:
	@echo "  Development setup complete."

fmt:
	$(CARGO) fmt

fmt-all:
	$(CARGO) fmt --

fmt-check:
	$(CARGO) fmt --all --check

# Integration tests use --features demo-disk so that init.rs enables the
# in-memory demo SimpleFs volumes when running outside of unit-test cfg(test).
test: setup-dev
	$(CARGO) test $(CARGO_FLAGS) --features demo-disk

test-lib:
	$(CARGO) test $(CARGO_FLAGS) --lib --features demo-disk

test-fast:
	$(CARGO) test $(CARGO_FLAGS) --features demo-disk --test io --test path

test-concurrency:
	$(CARGO) test $(CARGO_FLAGS) --features demo-disk --test scheduler --test condvar --test console --test keyboard

test-storage:
	$(CARGO) test $(CARGO_FLAGS) --features demo-disk --test fs_maintenance --test memory_manager --test page_table --test simplefs --test simplefs_recovery --test simplefs_fault_matrix

verify:
	sh ./scripts/verify.sh "$${VERIFY_TIER:-p3}"

verify-p0:
	sh ./scripts/verify.sh p0

verify-p1:
	sh ./scripts/verify.sh p1

verify-p2:
	sh ./scripts/verify.sh p2

verify-p3:
	sh ./scripts/verify.sh p3

check: check-host check-target

check-host: setup-dev
	$(CARGO) check $(CARGO_FLAGS)

check-target:
	$(CARGO) check $(CARGO_FLAGS) --target $(TARGET)

check-aarch64:
	$(CARGO) check $(CARGO_FLAGS) --target aarch64-unknown-none

check-riscv64:
	$(CARGO) check $(CARGO_FLAGS) --target riscv64gc-unknown-none-elf

check-aarch64-runtime:
	PROFILE="$(PROFILE)" \
		CRATE="$(CRATE)" \
		TARGET_DIR="$(TARGET_DIR)" \
		sh ./scripts/check-aarch64-runtime.sh

# Kernel build targets.  Ring3 ELF payload wrappers are built in-kernel
# (src/user/demo/); where the demo volume still needs a ring3 binary that no
# longer exists, a small placeholder ELF is provided inline in
# src/kernel/fs/demo.rs so the kernel builds independently.
build:
	$(CARGO) build $(CARGO_FLAGS) $(CARGO_PROFILE_FLAG) --target $(TARGET) --bin $(CRATE)

build-aarch64:
	$(CARGO) build $(CARGO_FLAGS) $(CARGO_PROFILE_FLAG) --target aarch64-unknown-none --bin $(CRATE)

build-riscv64:
	$(CARGO) build $(CARGO_FLAGS) $(CARGO_PROFILE_FLAG) --target riscv64gc-unknown-none-elf --bin $(CRATE)

clippy:
	$(CARGO) clippy $(CARGO_FLAGS) --all-targets -- -D warnings

run: build
	@if [ ! -x "$$(command -v qemu-system-x86_64)" ]; then \
		echo "qemu-system-x86_64 is not installed; cannot run the x86_64 kernel."; \
		exit 1; \
	fi
	qemu-system-x86_64 \
		-machine q35 \
		-cpu max \
		-smp 1 \
		-m 1G \
		-kernel "$(TARGET_DIR)/x86_64-unknown-none/$(PROFILE)/$(CRATE)" \
		-display none \
		-serial stdio \
		-no-reboot \
		-no-shutdown \
		-netdev user,id=net0 -device virtio-net-pci,netdev=net0

run-aarch64: build-aarch64
	@if [ ! -x "$$(command -v qemu-system-aarch64)" ]; then \
		echo "qemu-system-aarch64 is not installed; cannot run the aarch64 kernel."; \
		exit 1; \
	fi
	qemu-system-aarch64 \
		-machine virt \
		-cpu max \
		-smp 1 \
		-m 1G \
		-kernel "$(TARGET_DIR)/aarch64-unknown-none/$(PROFILE)/$(CRATE)" \
		-display none \
		-serial stdio \
		-no-reboot \
		-no-shutdown \
		-netdev user,id=net0 -device virtio-net-device,netdev=net0

run-riscv64: build-riscv64
	@if [ ! -x "$$(command -v qemu-system-riscv64)" ]; then \
		echo "qemu-system-riscv64 is not installed; cannot run the riscv64 kernel."; \
		exit 1; \
	fi
	qemu-system-riscv64 \
		-machine virt \
		-cpu rv64 \
		-smp 1 \
		-m 1G \
		-kernel "$(TARGET_DIR)/riscv64gc-unknown-none-elf/$(PROFILE)/$(CRATE)" \
		-display none \
		-serial stdio \
		-no-reboot \
		-no-shutdown \
		-netdev user,id=net0 -device virtio-net-device,netdev=net0

clean:
	$(CARGO) clean

# KASLR relocation table path.
KERNEL_ELF = $(TARGET_DIR)/$(TARGET)/$(PROFILE)/$(CRATE)
KASLR_RELOCS = src/arch/x86_64/kaslr_relocs.generated.rs

# Rebuild KASLR relocations after the kernel is built.
# Run `make build` twice for a fully self-consistent result:
#   Pass 1: build with existing relocs, generate new relocs.
#   Pass 2: rebuild with fresh relocs.
.PHONY: gen-kaslr-relocs
gen-kaslr-relocs:
	@if [ -f "$(KERNEL_ELF)" ]; then \
		cargo run --manifest-path tools/gen-kaslr-relocs/Cargo.toml -- \
			"$(KERNEL_ELF)" "$(KASLR_RELOCS)"; \
	else \
		echo "KASLR relocs: $(KERNEL_ELF) not found — skip gen (first build)"; \
	fi
