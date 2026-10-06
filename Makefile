# File: Makefile
# Purpose: Top-level build, test, and QEMU automation entrypoints for the kernel.

.DEFAULT_GOAL := help

CARGO ?= cargo
CARGO_FLAGS ?= --offline
CRATE ?= protofire
PROFILE ?= debug
# `PROFILE` defaults to debug because that is what a developer wants from the
# check targets; a release is the other profile unless someone asks otherwise,
# which is why it carries its own variable rather than borrowing that default.
RELEASE_PROFILE ?= release
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
		check-aarch64-host \
		check-riscv64 \
		check-unsafe-comments \
		check-user-access-windows \
		check-repo-integrity \
		check-docs \
		check-rfcs \
		check-payload-relocations \
		check-reproducible-build \
		release \
		check-perf-baseline \
		check-dead-code-allows \
		check-abi-mirror \
		check-layering \
		check-x8664-runtime \
		check-x8664-churn \
		check-riscv64-churn \
		check-aarch64-runtime \
		check-aarch64-smp-runtime \
		check-riscv64-runtime \
		check-riscv64-aia-runtime \
		check-riscv64-pci-runtime \
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
		'  make check-aarch64-host - type-check aarch64-unknown-linux-gnu, where the arch modules also build' \
		'  make check-riscv64  - run bare-metal type checks for riscv64gc-unknown-none-elf' \
		'  make check-unsafe-comments - fail if any configuration gained an undocumented `unsafe` block' \
		'  make check-user-access-windows - fail if a module outside `syscall/memory/user.rs` opens a user-access window' \
		'  make check-repo-integrity  - fail if a ref or the index names a missing git object' \
		'  make check-docs     - fail if a document cites a file the tree does not have' \
		'  make check-rfcs     - fail if an RFC number, status or the generated index is wrong' \
		'  make check-payload-relocations - fail if a demo payload refers outside itself' \
		'  make check-dead-code-allows  - fail if a file-level allow(dead_code) has no reason' \
		'  make check-reproducible-build - rebuild every artifact twice and compare bytes' \
		'  make release        - build and sign the release bundle (does not tag or publish)' \
		'  make check-perf-baseline - boot the demo and compare its measured work to the baseline' \
		'  make check-abi-mirror  - fail if the user-space ABI copy drifts from the kernel'"'"'s' \
		'  make check-layering - fail if a module gained a dependency the census does not have' \
		'  make check-x8664-runtime - run the headless single-CPU QEMU x86_64 demo smoke check' \
		'  make check-x8664-init-no-start - boot an init that asks for nothing, and reach the fallback' \
		'  make check-x8664-churn - exhaust the stack window and the TLB log, and check the fallbacks' \
		'  make check-riscv64-churn - the same churn on riscv64, whose window is one of the things it checks' \
		'  make check-aarch64-runtime - run the headless QEMU virt aarch64 fault/wait smoke check' \
		'  make check-riscv64-runtime - run the headless QEMU virt riscv64 demo smoke check' \
		'  make check-riscv64-aia-runtime - boot riscv64 on the AIA machine and check the IMSIC' \
		'  make check-riscv64-pci-runtime - boot riscv64 with a PCIe device and check the device-tree walk' \
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

# A `git commit` that is interrupted while it writes objects can leave a ref or
# the index naming something that is not there, and the first symptom is a
# later command failing with an error about an object it cannot read.  This
# names that state directly; it runs in well under a second, so it sits in the
# P0 tier where a broken working copy is caught before anything is built on it.
check-repo-integrity:
	sh ./scripts/check-repo-integrity.sh

# Documentation cites the tree constantly — every `src/...` path and every
# relative link is a claim that a file exists, and a citation of a file that
# has moved or never existed reads exactly like one that has not.  The scan is
# a filesystem walk, so it sits in the P0 tier beside the other checks that
# catch a broken working copy before anything is built on it.
check-docs:
	sh ./scripts/check-docs.sh

# The RFC directory is the one place a *number* carries meaning: code cites it,
# a later document supersedes it, and the index that lists it is generated from
# the documents rather than maintained by hand.  This checks the numbers, the
# statuses and the supersede links, and fails when the index has drifted.
check-rfcs:
	sh ./scripts/check-rfcs.sh

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
	$(CARGO) test $(CARGO_FLAGS) --features demo-disk --test io --test path --test fs_entries --test install

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

check: check-host check-target check-aarch64-host

check-host: setup-dev
	$(CARGO) check $(CARGO_FLAGS)

check-target:
	$(CARGO) check $(CARGO_FLAGS) --target $(TARGET)

# The aarch64 *host* configuration.  Every architecture module is written to
# compile on a host — that is what lets the tests build the same code the
# machine runs — so this configuration is part of the build's contract, and it
# went unnoticed for want of a gate: a `#[cfg]` on a module another module
# named left it unable to resolve on this target, and nothing checked.
check-aarch64-host:
	$(CARGO) check $(CARGO_FLAGS) --target aarch64-unknown-linux-gnu

check-aarch64:
	$(CARGO) check $(CARGO_FLAGS) --target aarch64-unknown-none

check-riscv64:
	$(CARGO) check $(CARGO_FLAGS) --target riscv64gc-unknown-none-elf

# Hold the line on undocumented `unsafe` blocks.  Every configuration records
# zero today and the lint is denied outright, so a new undocumented block fails
# in `make clippy` and `make clippy-targets`.  This target is the second,
# independent census: each configuration in
# `scripts/unsafe-comment-baseline.txt` may report no more than the count
# recorded there, and a count that *drops* has to be re-recorded in the same
# change (`sh scripts/check-unsafe-comments.sh --record`) so the baseline keeps
# telling the truth about the tree.  It is what would still catch a
# configuration no clippy target covers.  See docs/fmts/unsafe-and-safety.md §3.
check-unsafe-comments:
	sh ./scripts/check-unsafe-comments.sh

# Keep the user-access window — x86_64's AC, AArch64's PAN, RISC-V's SUM —
# opened from one module.  It is per-hart state, so a handler that opens it and
# then waits hands the permission to whatever runs next on that hart, and a
# helper that closes it on the way out closes the enclosing window too.  The
# window is opened in `syscall/memory/user.rs`, whose helpers scope it to a
# single copy; every other caller reaches user memory through them, and this
# gate refuses the first open-coded window somewhere else.
check-user-access-windows:
	sh ./scripts/check-user-access-windows.sh

# Hold the line on the kernel's module dependency graph.  The census in
# `scripts/layering-baseline.txt` records how often each module names every
# other one; a count that grows, a row that shrinks without the census being
# re-recorded, or an edge the census does not mention all fail.  The cycles it
# still lists (`fs` <-> `memory`, `process` <-> `memory`, `process` <->
# `network`, ...) are the layering debt, and the counts are the finish line for
# each cut; the baseline's own header argues the deliberate exceptions.  `sync`
# is the bottom of the graph now, so naming it is not a dependency to argue
# about.
check-layering:
	sh ./scripts/check-layering.sh

# Count the architecture gates that live outside `src/arch/`.  Porting the
# kernel to a fourth architecture should mean writing that architecture's own
# directory, and today it also means finding every `#[cfg(target_arch = "…")]`
# in the tree; `scripts/arch-fanout-baseline.txt` is the census, and the reader
# who wants a number should read it there.  This is a ratchet over that census —
# a count that grows fails, and a count that drops has to be re-recorded in the
# same change — so the wall `more hardware` runs into is at least visible and
# only gets shorter.  See §14 of docs/fmts/code-style.md.
check-arch-fanout:
	sh ./scripts/check-arch-fanout.sh

# A demo payload is copied out of its linker section and run at another
# address, so every reference it makes has to be relative to itself.  This
# reads the built image's relocation table and requires each payload section's
# entries to name that section — the check at the level where the defect
# actually appears (three exception handlers were addressed absolutely, from
# outside the section, and the disassembly-based tests could not see it).
check-payload-relocations:
	$(MAKE) build-x8664-demo
	sh ./scripts/check-payload-relocations.sh

# A release is only worth signing if someone else can rebuild it and get the
# same bytes, so the tree has to keep building the same bytes twice in a row.
# This is the expensive check of the artifacts themselves: two clean trees,
# all three architectures, and the demo disk, compared byte for byte.
check-reproducible-build:
	PROFILE="$(PROFILE)" \
		CRATE="$(CRATE)" \
		CARGO="$(CARGO)" \
		sh ./scripts/check-reproducible-build.sh

# A release is the source, the artifacts, and the ability to check one against
# the other.  This builds the four artifacts the reproducibility gate builds,
# gives each the name it ships under, signs each with a fresh one-time key, and
# verifies every signature with the verifier a user would use.  It does not
# tag or publish; CONTRIBUTING.md -> Releasing has the order around it.
release:
	PROFILE="$(RELEASE_PROFILE)" \
		CRATE="$(CRATE)" \
		CARGO="$(CARGO)" \
		sh ./scripts/make-release.sh

# A performance change should be judged by the work it does, not by how busy
# the host was, so this gate compares counters rather than seconds: it boots
# the demo with the profilers on and checks the single line
# `src/kernel/perf_baseline.rs` prints against the recorded rows in
# `scripts/perf-baseline.txt`.  It needs QEMU and a build with the profiler
# features, which is why it is a target of its own and not part of
# `make check`; a re-record is `sh scripts/check-perf-baseline.sh --record`.
check-perf-baseline:
	PROFILE="$(PROFILE)" \
		CRATE="$(CRATE)" \
		CARGO="$(CARGO)" \
		TARGET_DIR="$(TARGET_DIR)" \
		sh ./scripts/check-perf-baseline.sh

# A file-level `allow(dead_code)` is the one annotation the compiler cannot
# argue with, so the tree's convention is that it carries a reason and an exit
# condition.  This is the check that keeps the convention from eroding; two
# allows in this tree outlived their reasons before it existed.
check-dead-code-allows:
	sh ./scripts/check-dead-code-allows.sh

# The ABI records exist twice on purpose — `src/abi/` for the kernel and
# `src/user/shared/abi/` for the vendored user tree — so the copy needs a check
# rather than trust.  This one also fails a file in `src/abi/` that no `pub mod`
# declares, because a file the compiler never reads is not code: three of them
# sat there, one listing prctl codes that collided with the real ones.
check-abi-mirror:
	sh ./scripts/check-abi-mirror.sh

# Run a payload that was **not** rebuilt with the kernel: the bytes frozen on
# 2026-09-27 are shipped instead of the ones this build compiles, and the boot
# has to produce the same user output.  This is the only configuration in which
# "we do not break userspace" can be false — with a payload that is rebuilt
# whenever the kernel is, an ABI change would be invisible by construction.
check-abi-frozen-payload:
	FEATURES="demo-disk abi_frozen_payload" \
		PAYLOAD_SOURCE=frozen \
		X8664_RUNTIME_LOG="$${X8664_RUNTIME_LOG:-}" \
		sh ./scripts/check-x8664-runtime.sh

# The same gate on the second architecture: its payload is hand-written RISC-V
# assembly rather than a Rust section, which is the other shape the ABI has to
# keep working for a program that is not rebuilt.
check-abi-frozen-payload-riscv64:
	FEATURES="demo-disk abi_frozen_payload" \
		PAYLOAD_SOURCE=frozen \
		RISCV64_RUNTIME_LOG="$${RISCV64_RUNTIME_LOG:-}" \
		sh ./scripts/check-riscv64-runtime.sh

# And on aarch64, whose payload is a Rust section and whose entry point is not
# at its start — the third shape the ABI has to keep working.
check-abi-frozen-payload-aarch64:
	FEATURES="demo-disk abi_frozen_payload" \
		PAYLOAD_SOURCE=frozen \
		AARCH64_RUNTIME_LOG="$${AARCH64_RUNTIME_LOG:-}" \
		sh ./scripts/check-aarch64-runtime.sh

# Boot the kernel on a single emulated CPU with the demo disk and assert that
# the user programs actually run.  The SMP smoke cannot see a defect that
# takes one CPU down at a time, and a single CPU is what `make run` gives a
# developer, so this is the check a wedge like that has to fail.
check-x8664-runtime:
	PROFILE="$(PROFILE)" \
		CRATE="$(CRATE)" \
		TARGET_DIR="$(TARGET_DIR)" \
		sh ./scripts/check-x8664-runtime.sh

# The other half of the boot hand-off, and the only boot that reaches it: the
# disk's init program reads the declarations and asks for nothing to be
# started, so the supervisor has to start what is still pending when the
# hand-off's deadline passes.  Without this the fallback is code no boot runs —
# see `init_no_start` in Cargo.toml for why the switch is a feature.
check-x8664-init-no-start:
	FEATURES="demo-disk init_no_start" \
		INIT_NO_START=1 \
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

# The riscv64 counterpart.  Its stack window is younger than x86_64's, so this
# is where "riscv64 gets its stacks from a window, and the guard pages are
# really enforced" is checked rather than asserted — along with the
# invalidation grace that hands a retired slice out again.
check-riscv64-churn:
	PROFILE="$(PROFILE)" \
		CRATE="$(CRATE)" \
		TARGET_DIR="$(TARGET_DIR)" \
		sh ./scripts/check-riscv64-churn.sh

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

# The same kernel on the AIA machine, which is the only boot that reaches the
# IMSIC.  The default machine serves external interrupts from a PLIC, so every
# other gate — and every gate before this one — never touched the MSI path at
# all: it spoke an interface its target does not implement, and the difference
# showed up as an access fault the moment a boot asked for AIA.
check-riscv64-aia-runtime:
	PROFILE="$(PROFILE)" \
		CRATE="$(CRATE)" \
		TARGET_DIR="$(TARGET_DIR)" \
		sh ./scripts/check-riscv64-aia-runtime.sh

# Boot riscv64 with a PCIe device attached and check the device-tree walk.
# The window the device tree describes was never reached — the parser settled
# it when it read `reg`, and `compatible` comes after `reg` — and no gate had a
# device on the bus to notice.  This one does.
check-riscv64-pci-runtime:
	PROFILE="$(PROFILE)" \
		CRATE="$(CRATE)" \
		TARGET_DIR="$(TARGET_DIR)" \
		sh ./scripts/check-riscv64-pci-runtime.sh

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
# src/fs/demo.rs so the kernel builds independently.
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

# `-D clippy::undocumented_unsafe_blocks` is spelled out because the lint is
# allow-by-default: `-D warnings` alone does not turn it on.  The tree reached
# zero undocumented blocks and impls on 2026-09-27, which is when the ratchet
# that held the line could stop being the only thing watching for them; see
# docs/fmts/unsafe-and-safety.md §3.
clippy:
	$(CARGO) clippy $(CARGO_FLAGS) --all-targets -- \
		-D warnings -D clippy::undocumented_unsafe_blocks

# `clippy` above runs over the host target, and the machine-specific files —
# the drivers, the interrupt controllers, each architecture's page tables — are
# compiled only for a bare-metal target.  So those files were never linted with
# `-D warnings` at all: the tree carried fifteen missing-`# Safety` docs, two
# collapsible conditions and a handful of useless casts on the three bare-metal
# targets for as long as nobody asked.  This is the check that asks.  The
# aarch64 *host* configuration is included because every architecture module is
# written to compile there as well — and it is the one that takes
# `--all-targets`: the bare-metal targets have no test harness to build, the
# x86_64 host is what `make clippy` already covers, and the aarch64 host is
# where a test file that only compiles off x86_64 shows up.  A defect of
# exactly that shape (`src/memory/tests.rs` calling a lock-owner query that was
# compiled out when the host was not x86_64) reached an aarch64 CI runner
# because this loop did not build that configuration's tests.
# `aarch64-unknown-linux-gnu` stands in for the CI runner that is an aarch64
# machine; `x86_64-apple-darwin` stands in for the macOS and Windows ones, whose
# `target_os` is the one thing that differs from Linux here.  Both are host
# configurations, so both take `--all-targets`.  Neither check is a substitute
# for the runner — a Windows-only `cfg` would still slip through — but between
# them they cover every configuration a test file can fail to compile in.
#
# The three machine targets are also linted with the features the runtime gates
# build, because those are what ships: `demo-disk` decides which of
# `spawn_from_global`'s two `#[cfg]` arms is compiled, and a clippy lint that
# fires only in that arm (`needless_return`, here) went unnoticed until the ABI
# gate asked for the frozen payload.
CLIPPY_TARGETS = x86_64-unknown-none aarch64-unknown-none riscv64gc-unknown-none-elf aarch64-unknown-linux-gnu x86_64-apple-darwin
CLIPPY_BARE_METAL_TARGETS = x86_64-unknown-none aarch64-unknown-none riscv64gc-unknown-none-elf
CLIPPY_BARE_METAL_FEATURES = demo-disk abi_frozen_payload
# The other disk-content switch a runtime gate builds: an init program that
# asks for nothing, which is what reaches the hand-off's fallback
# (`make check-x8664-init-no-start`).  One target is enough — the switch is in
# the payload body every machine emits.
CLIPPY_NO_START_TARGET = x86_64-unknown-none
CLIPPY_NO_START_FEATURES = demo-disk init_no_start

clippy-targets:
	@for target in $(CLIPPY_TARGETS); do \
		echo "==> clippy $$target"; \
		case "$$target" in \
			aarch64-unknown-linux-gnu|x86_64-apple-darwin) extra="--all-targets" ;; \
			*) extra="" ;; \
		esac; \
		$(CARGO) clippy $(CARGO_FLAGS) $$extra --target $$target -- \
			-D warnings -D clippy::undocumented_unsafe_blocks || exit 1; \
	done
	@for target in $(CLIPPY_BARE_METAL_TARGETS); do \
		echo "==> clippy $$target ($(CLIPPY_BARE_METAL_FEATURES))"; \
		$(CARGO) clippy $(CARGO_FLAGS) --target $$target \
			--features "$(CLIPPY_BARE_METAL_FEATURES)" -- \
			-D warnings -D clippy::undocumented_unsafe_blocks || exit 1; \
	done
	@for target in $(CLIPPY_NO_START_TARGET); do \
		echo "==> clippy $$target ($(CLIPPY_NO_START_FEATURES))"; \
		$(CARGO) clippy $(CARGO_FLAGS) --target $$target \
			--features "$(CLIPPY_NO_START_FEATURES)" -- \
			-D warnings -D clippy::undocumented_unsafe_blocks || exit 1; \
	done

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
