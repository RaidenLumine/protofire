# File: Makefile
# Purpose: Top-level build, test, and QEMU automation entrypoints for the kernel.

.DEFAULT_GOAL := help

CARGO ?= cargo
CARGO_FLAGS ?= --offline
CRATE ?= protofire
PROFILE ?= debug
TARGET_DIR ?= target
# Guest CPUs for every QEMU run target.  One is the default because most of the
# suite is single-CPU by design, but the kernel brings up APs and schedules on
# them, so `make run-x8664 SMP=4` is how you exercise the SMP paths locally —
# in particular the cross-CPU TLB-shootdown interactions that a single CPU
# cannot reach at all.
SMP ?= 1
TARGET ?= x86_64-unknown-none

ifeq ($(PROFILE),release)
CARGO_PROFILE_FLAG := --release
else ifeq ($(PROFILE),debug)
CARGO_PROFILE_FLAG :=
else
$(error PROFILE must be either debug or release)
endif

.PHONY: help \
		doctor \
		fmt \
		fmt-all \
		fmt-check \
		test \
		test-lib \
		test-fast \
		test-concurrency \
		test-storage \
		test-fat32 \
		test-usb \
		test-gpu \
		test-parsers \
		verify \
		verify-p0 \
		verify-p1 \
		verify-p2 \
		verify-p3 \
		check \
		check-host \
		check-target \
		check-aarch64 \
		check-riscv64 \
		check-unsafe-comments \
		check-layering \
		check-x8664-runtime \
		check-x8664-churn \
		check-aarch64-runtime \
		check-aarch64-smp-runtime \
		check-riscv64-runtime \
		check-riscv64-smp-runtime \
		build \
		build-aarch64 \
		build-aarch64-image \
		build-aarch64-image-plain \
		build-riscv64 \
		build-x8664-demo \
		build-aarch64-demo \
		build-riscv64-demo \
		clippy \
		run \
		run-x8664-headless \
		run-aarch64 \
		run-riscv64 \
		run-aarch64-headless \
		run-riscv64-headless \
		clean \
		setup-dev \
		install-hooks

help:
	@printf '%s\n' \
		'Available targets:' \
		'  make doctor         - check the environment, failing if a required tool is absent' \
		'  make verify         - run the default P3 verification gate (override with VERIFY_TIER=p0..p3)' \
		'  make verify-p0      - format check + host/x86_64/aarch64 build checks + header coverage' \
		'  make verify-p1      - P0 plus fast concurrency/path/I-O/ABI regressions' \
		'  make verify-p2      - P1 plus storage/recovery/fault-matrix regressions' \
		'  make verify-p3      - P2 plus clippy and optional AArch64 runtime smoke' \
		'  make check          - run both host and bare-metal type checks' \
		'  make check-aarch64  - run bare-metal type checks for aarch64-unknown-none' \
		'  make check-riscv64  - run bare-metal type checks for riscv64gc-unknown-none-elf' \
		'  make check-unsafe-comments - fail if any configuration gained an undocumented `unsafe` block' \
		'  make check-layering - fail if a module gained a dependency the census does not have' \
		'  make check-x8664-runtime - run the headless single-CPU QEMU x86_64 demo smoke check' \
		'  make check-x8664-churn - exhaust the stack window and the TLB log, and check the fallbacks' \
		'  make check-aarch64-runtime - run the headless QEMU virt aarch64 fault/wait smoke check' \
		'  make check-riscv64-runtime - run the headless QEMU virt riscv64 demo smoke check' \
		'  make check-riscv64-smp-runtime - boot riscv64 on several harts and check they come up' \
		'  make test           - run host-side unit and integration tests' \
		'  make test-lib       - run library unit tests only' \
		'  make test-fast      - run path/I-O/syscall/user integration regressions' \
		'  make test-concurrency - run scheduler/input/condvar concurrency regressions' \
		'  make test-storage   - run filesystem/recovery/fault-injection regressions' \
		'  make test-usb       - run USB Mass Storage (MSD) integration tests' \
		'  make test-gpu       - run VIRGL 3D demo renderer integration tests' \
		'  make test-parsers   - run the deterministic in-tree parser fuzz harnesses' \
		'  make fmt            - format the source tree' \
		'  make fmt-all        - format the source tree and all dependencies' \
		'  make fmt-check      - verify formatting without modifying files' \
		'  make build          - build the bare-metal kernel ELF (PROFILE=debug|release)' by default \
		'  make build-x8664    - build the bare-metal kernel ELF (PROFILE=debug|release)' \
		'  make build-aarch64  - build the aarch64 bare-metal kernel ELF for QEMU virt' \
		'  make build-aarch64-image - build the aarch64 kernel as the bootable arm64 Image (device tree)' \
		'  make build-riscv64  - build the riscv64 bare-metal kernel ELF for QEMU virt' \
		'  make build-x8664-demo - build x86_64 kernel with the in-memory demo disk (shell)' \
		'  make build-aarch64-demo - build aarch64 kernel with the in-memory demo disk (shell)' \
		'  make build-riscv64-demo - build riscv64 kernel with the in-memory demo disk (shell)' \
		'  make clippy         - run clippy for all targets' \
		'  make run             - x86_64 demo shell on QEMU q35, interactive over serial (no window)' \
		'  make run-x8664       - alias of make run (x86_64 serial interactive shell)' \
		'  make run-x8664-headless - x86_64 smoke (no demo-disk, no display)' \
		'  make run-aarch64    - aarch64 demo shell on QEMU virt, interactive over serial' \
		'  make run-riscv64    - riscv64 demo shell on QEMU virt, interactive over serial' \
		'  make run-aarch64-headless - aarch64 smoke (no demo-disk, no display)' \
		'  make run-riscv64-headless - riscv64 smoke (no demo-disk, no display)' \
		'  make clean          - remove Cargo artifacts' \
		'  make setup-dev      - no-op (runtime and demo crates are co-located in-repo)' \
		'  make install-hooks  - install the commit-msg git hook (once per clone)' \
		'  (disk image and ISO targets are not implemented yet)'

doctor:
	sh ./scripts/doctor.sh

# The co-located runtime and demo crates live inside the kernel crate
# (src/user/shared/, src/user/demo/).  No symlinks needed.
setup-dev:
	@echo "  Development setup complete."

# Install the repository git hooks (commit-msg validation).  Run once per
# clone; `git config core.hooksPath` is stored in the local .git/config and
# is not part of the tracked tree.
install-hooks:
	git config core.hooksPath scripts/hooks
	@echo "  Git hooks installed: scripts/hooks (commit-msg validation active)"

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
	$(CARGO) test $(CARGO_FLAGS) --features demo-disk --test fs_maintenance --test memory_manager --test page_table --test simplefs --test simplefs_recovery --test simplefs_fault_matrix --test simplefs_undo_property --test fat32

test-fs-locking:
	@echo "Running Filesystem Lock-Discipline Tests..."
	$(CARGO) test $(CARGO_FLAGS) --features demo-disk --test sync_lock
	@echo "Filesystem lock-discipline tests completed"

test-fat32:
	@echo "Running FAT32 Filesystem Integration Tests..."
	$(CARGO) test $(CARGO_FLAGS) --features demo-disk --test fat32
	@echo "FAT32 tests completed"

test-usb:
	@echo "Running USB MSD Integration Tests..."
	$(CARGO) test $(CARGO_FLAGS) --features demo-disk --test usb_msd
	@echo "USB MSD tests completed"

test-gpu:
	@echo "Running VIRGL 3D Demo Renderer Integration Tests..."
	$(CARGO) test $(CARGO_FLAGS) --features demo-disk --test virgl_demo
	@echo "VIRGL 3D demo tests completed"

test-parsers:
	@echo "Running Deterministic Parser Fuzz Harnesses..."
	$(CARGO) test $(CARGO_FLAGS) --features demo-disk --test parser_fuzz
	@echo "Parser fuzz harnesses completed"

test-service:
	@echo "Running Service Registry and /service Filesystem Integration Tests..."
	$(CARGO) test $(CARGO_FLAGS) --features demo-disk --test servicefs
	@echo "Service filesystem tests completed"

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

# Hold the line on undocumented `unsafe` blocks.  The tree has far more
# `unsafe` blocks than written safety arguments, so the lint cannot be a gate
# on its own: switched to `deny` it fails with 2,867 diagnostics across the
# four configurations today, and the honest answer to that is a comment on
# every block that argues nothing.  This is a ratchet instead.  Each
# configuration in
# `scripts/unsafe-comment-baseline.txt` may report no more than the count
# recorded there, and a count that *drops* has to be re-recorded in the same
# change (`sh scripts/check-unsafe-comments.sh --record`) so the baseline keeps
# telling the truth about the tree.  See docs/fmts/unsafe-and-safety.md §3.
check-unsafe-comments:
	sh ./scripts/check-unsafe-comments.sh

# Hold the line on the kernel's module dependency graph.  The census in
# `scripts/layering-baseline.txt` records how often each module names every
# other one; a count that grows, a row that shrinks without the census being
# re-recorded, or an edge the census does not mention all fail.  The cycles it
# still lists (`process` <-> `fs`, `memory` <-> `fs`, ...) are the layering
# debt, and the counts are the finish line for each cut.  `sync` is the bottom
# of the graph now, so naming it is not a dependency to argue about.
check-layering:
	sh ./scripts/check-layering.sh

# Boot the kernel on a single emulated CPU with the demo disk and assert that
# the user programs actually run.  The SMP smoke cannot see a defect that
# takes one CPU down at a time, and a single CPU is what `make run` gives a
# developer, so this is the check a wedge like that has to fail.
check-x8664-runtime:
	PROFILE="$(PROFILE)" \
		CRATE="$(CRATE)" \
		TARGET_DIR="$(TARGET_DIR)" \
		sh ./scripts/check-x8664-runtime.sh

# Boot with the stack-window churn: ask the window for more stacks than it has
# and the invalidation log for more requests than it can hold, then check the
# counts that come back.  A diagnostic rather than a gate — see the script.
check-x8664-churn:
	PROFILE="$(PROFILE)" \
		CRATE="$(CRATE)" \
		TARGET_DIR="$(TARGET_DIR)" \
		sh ./scripts/check-x8664-churn.sh

check-aarch64-runtime:
	PROFILE="$(PROFILE)" \
		CRATE="$(CRATE)" \
		TARGET_DIR="$(TARGET_DIR)" \
		sh ./scripts/check-aarch64-runtime.sh

# The riscv64 counterpart of the aarch64 smoke check.  riscv64 was the one
# architecture whose kernel was never booted by a gate, and the two defects that
# hiding cost — a stack guard reported as installed that was not, and an SBI
# call that clobbered the register holding the tick count — are both invisible
# to a type check and loud in a boot.
check-riscv64-runtime:
	PROFILE="$(PROFILE)" \
		CRATE="$(CRATE)" \
		TARGET_DIR="$(TARGET_DIR)" \
		sh ./scripts/check-riscv64-runtime.sh

# Boot riscv64 on several harts and assert that the SBI HSM starts found them.
# The hart IDs have to come from the device tree, and the hart the kernel is
# already running on has to be skipped — QEMU gives the reset to whichever hart
# it likes, and asking SBI to start the running hart is an error, not a start.
check-riscv64-smp-runtime:
	PROFILE="$(PROFILE)" \
		CRATE="$(CRATE)" \
		TARGET_DIR="$(TARGET_DIR)" \
		SMP_CPUS="$(SMP)" \
		sh ./scripts/check-riscv64-smp.sh

# Boot the kernel on several emulated CPUs and assert that the APs came up and
# that it is still making progress afterwards.  Single-CPU runs cannot reach
# the cross-CPU paths at all, so this is the only check that exercises them.
check-aarch64-smp-runtime:
	PROFILE="$(PROFILE)" \
		CRATE="$(CRATE)" \
		TARGET_DIR="$(TARGET_DIR)" \
		SMP_CPUS="$(SMP)" \
		sh ./scripts/check-aarch64-smp.sh

check-smp-runtime:
	PROFILE="$(PROFILE)" \
		CRATE="$(CRATE)" \
		TARGET_DIR="$(TARGET_DIR)" \
		SMP_CPUS="$(SMP)" \
		sh ./scripts/check-smp-runtime.sh

# Kernel build targets.  Ring3 ELF payload wrappers are built in-kernel
# (src/user/demo/); where the demo volume still needs a ring3 binary that no
# longer exists, a small placeholder ELF is provided inline in
# src/kernel/fs/demo.rs so the kernel builds independently.
build-x8664:
	$(CARGO) build $(CARGO_FLAGS) $(CARGO_PROFILE_FLAG) --target $(TARGET) --bin $(CRATE)

# Like build-x8664 but links the in-memory demo disk, so `make run` boots the
# interactive ring-3 shell over -serial stdio instead of idling.
build-x8664-demo:
	$(CARGO) build $(CARGO_FLAGS) $(CARGO_PROFILE_FLAG) --target $(TARGET) --bin $(CRATE) --features demo-disk

build-aarch64:
	$(CARGO) build $(CARGO_FLAGS) $(CARGO_PROFILE_FLAG) --target aarch64-unknown-none --bin $(CRATE)

# The bootable form: QEMU hands a device tree to a kernel only on the Linux boot
# path, which it recognises by the arm64 `Image` header.  Everything that boots
# aarch64 uses this; the ELF above stays the artifact to debug with.  See
# scripts/build-aarch64-image.sh.
build-aarch64-image:
	PROFILE="$(PROFILE)" \
		CRATE="$(CRATE)" \
		TARGET_DIR="$(TARGET_DIR)" \
		FEATURES="demo-disk" \
		sh ./scripts/build-aarch64-image.sh

# The same Image without the in-memory demo disk, for the headless smoke that
# exists to watch a boot that has nothing to run.
build-aarch64-image-plain:
	PROFILE="$(PROFILE)" \
		CRATE="$(CRATE)" \
		TARGET_DIR="$(TARGET_DIR)" \
		FEATURES="" \
		IMAGE="$(TARGET_DIR)/aarch64-unknown-none/$(PROFILE)/$(CRATE)-plain.img" \
		sh ./scripts/build-aarch64-image.sh

# Like build-aarch64 but links the in-memory demo disk so the interactive
# ring-3 shell boots over -serial stdio (no display device attached).
build-aarch64-demo:
	$(CARGO) build $(CARGO_FLAGS) $(CARGO_PROFILE_FLAG) --target aarch64-unknown-none --bin $(CRATE) --features demo-disk

build-riscv64:
	$(CARGO) build $(CARGO_FLAGS) $(CARGO_PROFILE_FLAG) --target riscv64gc-unknown-none-elf --bin $(CRATE)

# Like build-riscv64 but links the in-memory demo disk so the interactive
# ring-3 shell boots over -serial stdio (no display device attached).
build-riscv64-demo:
	$(CARGO) build $(CARGO_FLAGS) $(CARGO_PROFILE_FLAG) --target riscv64gc-unknown-none-elf --bin $(CRATE) --features demo-disk

build: build-x8664

clippy:
	$(CARGO) clippy $(CARGO_FLAGS) --all-targets -- -D warnings

# Run targets are pure serial-terminal sessions: QEMU opens no window and no
# display/input device is attached, so the demo ring-3 shell is fully
# interactive over -serial stdio (iteration and CI never need a display).  The
# kernel display drivers (virtio-gpu / virtio-input / framebuffer console) stay
# in the tree but go cold without a device to drive.
#
# QEMU 8.x `virt` machines default each virtio-mmio transport to *legacy* mode
# (force-legacy=true => version register reads 1), but the kernel drives the
# modern register layout and requires version 2.  Opt every transport (here,
# the attached virtio-net-device) into the modern interface.
VIRT_FORCE_LEGACY = -global virtio-mmio.force-legacy=false

# Boot the kernel on QEMU q35 with the interactive ring-3 shell over -serial
# stdio.  Needs --features demo-disk so the shell and the in-memory demo
# volumes are built in.  No display device is attached (pure serial terminal).
run-x8664: build-x8664-demo
	@if [ ! -x "$$(command -v qemu-system-x86_64)" ]; then \
		echo "qemu-system-x86_64 is not installed; cannot run the x86_64 kernel."; \
		exit 1; \
	fi
	qemu-system-x86_64 \
		-machine q35 \
		-cpu max \
		-smp $(SMP) \
		-m 1G \
		-kernel "$(TARGET_DIR)/x86_64-unknown-none/$(PROFILE)/$(CRATE)" \
		-display none \
		-serial stdio \
		-no-reboot \
		-no-shutdown \
		-netdev user,id=net0 -device virtio-net-pci,netdev=net0

# Original headless smoke: no display device, no demo-disk shell (idle banner).
run-x8664-headless: build-x8664
	@if [ ! -x "$$(command -v qemu-system-x86_64)" ]; then \
		echo "qemu-system-x86_64 is not installed; cannot run the x86_64 kernel."; \
		exit 1; \
	fi
	qemu-system-x86_64 \
		-machine q35 \
		-cpu max \
		-smp $(SMP) \
		-m 1G \
		-kernel "$(TARGET_DIR)/x86_64-unknown-none/$(PROFILE)/$(CRATE)" \
		-display none \
		-serial stdio \
		-no-reboot \
		-no-shutdown \
		-netdev user,id=net0 -device virtio-net-pci,netdev=net0

# Boot the aarch64 kernel on QEMU virt driving the interactive ring-3 shell
# (demo-disk) over -serial stdio.  Pure serial terminal: no display or input
# device is attached, so the virtio-gpu/virtio-keyboard drivers stay cold.
run-aarch64: build-aarch64-image
	@if [ ! -x "$$(command -v qemu-system-aarch64)" ]; then \
		echo "qemu-system-aarch64 is not installed; cannot run the aarch64 kernel."; \
		exit 1; \
	fi
	qemu-system-aarch64 \
		-machine virt \
		$(VIRT_FORCE_LEGACY) \
		-cpu max \
		-smp $(SMP) \
		-m 1G \
		-kernel "$(TARGET_DIR)/aarch64-unknown-none/$(PROFILE)/$(CRATE).img" \
		-display none \
		-serial stdio \
		-no-reboot \
		-no-shutdown \
		-netdev user,id=net0 -device virtio-net-device,netdev=net0

# Boot the riscv64 kernel on QEMU virt driving the interactive ring-3 shell
# (demo-disk) over -serial stdio, mirroring run-aarch64 (pure serial terminal,
# no display or input device attached).
run-riscv64: build-riscv64-demo
	@if [ ! -x "$$(command -v qemu-system-riscv64)" ]; then \
		echo "qemu-system-riscv64 is not installed; cannot run the riscv64 kernel."; \
		exit 1; \
	fi
	qemu-system-riscv64 \
		-machine virt \
		$(VIRT_FORCE_LEGACY) \
		-cpu rv64 \
		-smp $(SMP) \
		-m 1G \
		-kernel "$(TARGET_DIR)/riscv64gc-unknown-none-elf/$(PROFILE)/$(CRATE)" \
		-display none \
		-serial stdio \
		-no-reboot \
		-no-shutdown \
		-netdev user,id=net0 -device virtio-net-device,netdev=net0

# Original headless aarch64 smoke: no display device, no demo-disk shell
# (idle banner).  Mirrors the x86 run-x8664-headless target.
run-aarch64-headless: build-aarch64-image-plain
	@if [ ! -x "$$(command -v qemu-system-aarch64)" ]; then \
		echo "qemu-system-aarch64 is not installed; cannot run the aarch64 kernel."; \
		exit 1; \
	fi
	qemu-system-aarch64 \
		-machine virt \
		-cpu max \
		-smp $(SMP) \
		-m 1G \
		-kernel "$(TARGET_DIR)/aarch64-unknown-none/$(PROFILE)/$(CRATE)-plain.img" \
		-display none \
		-serial stdio \
		-no-reboot \
		-no-shutdown \
		-netdev user,id=net0 -device virtio-net-device,netdev=net0

# Original headless riscv64 smoke: no display device, no demo-disk shell
# (idle banner).  Mirrors the x86 run-x8664-headless target.
run-riscv64-headless: build-riscv64
	@if [ ! -x "$$(command -v qemu-system-riscv64)" ]; then \
		echo "qemu-system-riscv64 is not installed; cannot run the riscv64 kernel."; \
		exit 1; \
	fi
	qemu-system-riscv64 \
		-machine virt \
		-cpu rv64 \
		-smp $(SMP) \
		-m 1G \
		-kernel "$(TARGET_DIR)/riscv64gc-unknown-none-elf/$(PROFILE)/$(CRATE)" \
		-display none \
		-serial stdio \
		-no-reboot \
		-no-shutdown \
		-netdev user,id=net0 -device virtio-net-device,netdev=net0

run: run-x8664

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
