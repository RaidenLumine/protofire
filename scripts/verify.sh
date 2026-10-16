#!/usr/bin/env sh
# File: scripts/verify.sh
# Purpose: Tiered verification script that runs P0/P1/P2/P3 quality gates.

set -eu

cd "$(dirname "$0")/.."

PROFILE="${PROFILE:-debug}"
RUN_X86_64_RUNTIME="${RUN_X86_64_RUNTIME:-0}"
RUN_AARCH64_RUNTIME="${RUN_AARCH64_RUNTIME:-0}"
RUN_RISCV64_RUNTIME="${RUN_RISCV64_RUNTIME:-0}"
RUN_SMP_RUNTIME="${RUN_SMP_RUNTIME:-0}"
RUN_PERF_BASELINE="${RUN_PERF_BASELINE:-0}"
VERIFY_TIER="${1:-${VERIFY_TIER:-p2}}"

case "$PROFILE" in
    debug|release) ;;
    *)
        printf 'unsupported PROFILE: %s\n' "$PROFILE" >&2
        exit 1
        ;;
esac

case "$VERIFY_TIER" in
    p0|P0) VERIFY_TIER="p0" ;;
    p1|P1) VERIFY_TIER="p1" ;;
    p2|P2) VERIFY_TIER="p2" ;;
    p3|P3) VERIFY_TIER="p3" ;;
    *)
        printf 'unsupported VERIFY_TIER: %s\n' "$VERIFY_TIER" >&2
        exit 1
        ;;
esac

run_make_step() {
    description="$1"
    target="$2"
    shift 2
    printf '==> verify[%s]: %s\n' "$VERIFY_TIER" "$description"
    make "$target" PROFILE="$PROFILE" "$@"
}

check_source_headers() {
    total_files=0
    path_headers=0
    blank_headers=0
    separated_headers=0

    # Every `.rs` file in the repository must open with:
    #   line 1: `//! <relative_path>`
    #   line 2: `//!` (blank)
    #   followed by the `//!` description lines,
    # and a blank line must separate the whole `//!` header block from the
    # first body line (the convention requested by the maintainer).
    #
    # "In the repository" leaves out what `.gitignore` covers — `target/` is
    # the case this always had to skip — and one generated file that is
    # tracked rather than ignored: the KASLR relocation table
    # (`src/arch/x86_64/kaslr_relocs.generated.rs`).  It is written by
    # `make gen-kaslr-relocs`, compiled in by the `kaslr` build, and compared
    # against a fresh generation by `make check-x8664-kaslr-runtime`; a
    # hand-written header is not something a generator can meaningfully carry,
    # and the gate that keeps it honest is the comparison, not this one.  A
    # file that is not added yet is still checked, because that is where a
    # missing header is.
    files="$(git ls-files -z --cached --others --exclude-standard -- '*.rs' \
        | tr '\0' '\n' \
        | grep -v -x 'src/arch/x86_64/kaslr_relocs.generated.rs' \
        | sort)"
    for file in $files; do
        [ -f "$file" ] || continue
        total_files=$((total_files + 1))
        relative_path="$file"

        first_line="$(sed -n '1p' "$file")"
        second_line="$(sed -n '2p' "$file")"

        if [ "$first_line" = "//! $relative_path" ]; then
            path_headers=$((path_headers + 1))
        fi

        if [ "$second_line" = "//!" ]; then
            blank_headers=$((blank_headers + 1))
        fi

        # The first non-`//!`, non-blank line must come at least two lines
        # after the last `//!` header line (i.e. one blank line between).
        if awk '
            NR == 1 && $0 !~ /^\/\/!/ { exit 0 }
            $0 ~ /^\/\/!/ { last = NR; next }
            $0 == "" { next }
            { exit (NR - last >= 2) ? 0 : 1 }
        ' "$file"; then
            separated_headers=$((separated_headers + 1))
        fi
    done

    printf 'header coverage: path=%s blank=%s separated=%s total=%s\n' \
        "$path_headers" "$blank_headers" "$separated_headers" "$total_files"

    if [ "$path_headers" -ne "$total_files" ] \
        || [ "$blank_headers" -ne "$total_files" ] \
        || [ "$separated_headers" -ne "$total_files" ]; then
        printf 'source header coverage check failed\n' >&2
        return 1
    fi
}

check_commit_hooks() {
    hooks_path="$(git config --get core.hooksPath 2>/dev/null || true)"
    if [ -n "$hooks_path" ] && [ -x "$hooks_path/commit-msg" ]; then
        printf 'commit hook: installed (%s/commit-msg)\n' "$hooks_path"
    else
        printf 'commit hook: NOT installed — run `make install-hooks`\n' >&2
        return 1
    fi
}

run_p0() {
    # P0 keeps the baseline strict: format, multi-target builds, and source headers.
    run_make_step "make check-repo-integrity" check-repo-integrity
    run_make_step "make check-docs" check-docs
    run_make_step "make check-make-targets" check-make-targets
    run_make_step "make check-rfcs" check-rfcs
    run_make_step "make fmt-check" fmt-check
    run_make_step "make check (host + x86_64 target)" check
    run_make_step "make check-aarch64" check-aarch64
    run_make_step "make build" build
    run_make_step "make build-aarch64" build-aarch64

    printf '==> verify[%s]: source header coverage\n' "$VERIFY_TIER"
    check_source_headers

    printf '==> verify[%s]: commit message hook\n' "$VERIFY_TIER"
    check_commit_hooks
}

run_p1() {
    # P1 adds the fast host regressions that catch wake-order, ABI, and path drift.
    run_p0
    run_make_step "make test-lib" test-lib
    run_make_step "make test-concurrency" test-concurrency
    run_make_step "make test-fast" test-fast
}

run_p2() {
    # P2 extends the gate to storage and recovery suites, including fault matrices.
    run_p1
    run_make_step "make test-storage" test-storage
}

run_p3() {
    # P3 is the release-grade gate: static analysis plus optional QEMU runtime
    # smoke.  The x86_64 smoke boots a single CPU and is what a wedge that
    # stops the machine where the multi-CPU run would keep going has to fail;
    # the SMP smoke is the only check anywhere that boots more than one CPU,
    # which is the only way the cross-CPU paths run at all; and each of the
    # three architectures has a smoke of its own, so no target's kernel can go
    # un-booted.  They stay opt-in because they are slow and need QEMU.
    run_p2
    # The suites that have a target of their own and had no tier that called
    # them: a test target outside every gate is a target that rots, and this is
    # not hypothetical — `syscall_abi_golden` sat red for a release because no
    # tier ran it, and `make test` was the only thing that could have seen it.
    run_make_step "make test-fs-locking" test-fs-locking
    run_make_step "make test-service" test-service
    run_make_step "make test-usb" test-usb
    run_make_step "make test-gpu" test-gpu
    run_make_step "make test-parsers" test-parsers
    # The one boot that goes through a loader rather than QEMU's own hand-off:
    # the Multiboot2 memory map, and the ELF a real loader will accept.
    run_make_step "make check-x8664-iso" check-x8664-iso
    run_make_step "make clippy" clippy
    run_make_step "make clippy-targets" clippy-targets
    run_make_step "make check-unsafe-comments" check-unsafe-comments
    run_make_step "make check-user-access-windows" check-user-access-windows
    run_make_step "make check-layering" check-layering
    run_make_step "make check-arch-fanout" check-arch-fanout
    run_make_step "make check-payload-relocations" check-payload-relocations
    # And the generated table beside it: the KASLR relocations are what a
    # relocated image would be rewritten with, they are not compiled in, and
    # nothing else in the tree looks at them — the pool's move out of the
    # load segments silently cost the table 45 entries no gate could see.
    run_make_step "make check-kaslr-relocs" check-kaslr-relocs
    run_make_step "make check-dead-code-allows" check-dead-code-allows
    run_make_step "make check-status-rows" check-status-rows
    run_make_step "make check-ntfs-image" check-ntfs-image
    # And every configuration the manifest declares, which is the one gate
    # that builds the switches no boot hands to a `check-*` target.
    run_make_step "make check-feature-matrix" check-feature-matrix
    run_make_step "make check-abi-mirror" check-abi-mirror
    # The release artifacts themselves: the same source built twice in two
    # clean trees has to come out byte for byte the same, or a signature over
    # one release certifies a build nobody can reproduce.  It is the slowest
    # static gate here because it builds everything twice.
    run_make_step "make check-reproducible-build" check-reproducible-build
    # The one gate that compares work rather than outcome: it boots the demo
    # with the profilers on and checks the counters that boot reported against
    # the recorded baseline.  Opt-in like the smokes because it needs QEMU and
    # a build with the profiler features; unlike them it does not mind a busy
    # host, because the rows a schedule can still move carry a tolerance
    # rather than an assumption that the machine is idle.  The second boot is
    # the same demo on four CPUs, where the work a single-CPU boot cannot do at
    # all — waking the APs, the per-CPU tick, the IPIs a TLB shootdown sends —
    # is part of the comparison instead of invisible to it.
    if [ "$RUN_PERF_BASELINE" = "1" ]; then
        run_make_step "make check-perf-baseline" check-perf-baseline
        run_make_step "make check-perf-baseline-smp" check-perf-baseline-smp
        run_make_step "make check-perf-baseline-disk" check-perf-baseline-disk
        run_make_step "make check-perf-baseline-numa" check-perf-baseline-numa
        run_make_step "make check-perf-baseline-net" check-perf-baseline-net
    else
        printf '==> verify[%s]: skipping the boot-work baseline (set RUN_PERF_BASELINE=1 to enable)\n' \
            "$VERIFY_TIER"
    fi
    if [ "$RUN_X86_64_RUNTIME" = "1" ]; then
        run_make_step "make check-x8664-runtime" check-x8664-runtime
        # And the same kernel relocated: the KASLR table is generated, so
        # this is the only gate that proves it still describes the image it
        # is compiled into, and the only boot that runs the copy.
        run_make_step "make check-x8664-kaslr-runtime" check-x8664-kaslr-runtime
        # And a machine with very little RAM: the other boots here all have a
        # gigabyte or more, so nothing notices the kernel's demand for memory
        # growing.  This asserts the minimum as a capability — the machine's
        # own number, the pool clamped to it, and the ring-3 shell reached.
        run_make_step "make check-x8664-low-memory" check-x8664-low-memory
        # The same machine with a real filesystem image on its USB disk rather
        # than a single sector: the reads fill and refill the controller's
        # rings, which is where the ring-reuse defect lived, and the boot's own
        # writes are what show the volume reached the host's image.
        run_make_step "make check-x8664-usb-disk" check-x8664-usb-disk
        # And the install path: zones put onto a disk `sgdisk` made — a
        # stranger's table with a partition this kernel has no name for — then
        # booted.  It is the gate a real machine's disk needs, and the one
        # that catches a checksum only an outside writer can falsify.
        run_make_step "make check-x8664-install" check-x8664-install
        # And the case that disk cannot cover: a device plugged into a hub
        # *after* the boot scan, which is what the hub's status-change
        # endpoint exists for.  The plug is QEMU's, so a guest that ignores it
        # cannot pass by reading its own state.
        run_make_step "make check-x8664-usb-hotplug" check-x8664-usb-hotplug
        # The same machine with its image on an NVMe device: the only gate
        # that attaches one, and therefore the only place the NVMe driver's
        # bring-up runs at all.
        run_make_step "make check-x8664-nvme" check-x8664-nvme
        # And audio, whose samples the host's own audio backend is the
        # instrument for: no other gate attaches an audio device.
        run_make_step "make check-x8664-hda" check-x8664-hda
        # The other half of the boot hand-off: a disk whose init reads the
        # declarations and asks for nothing, so the supervisor's fallback is
        # what starts the services.
        run_make_step "make check-x8664-init-no-start" check-x8664-init-no-start
        # The same boot with a payload that was frozen on 2026-09-27 rather
        # than compiled with the kernel: the only configuration in which an ABI
        # change can break a program that is not rebuilt alongside it.
        run_make_step "make check-abi-frozen-payload" check-abi-frozen-payload
        # And the boot that asks for more than the stack window and the
        # invalidation log can hold, which is the only one that reaches either
        # fallback: a fallback nobody boots is a fallback nobody has tested.
        run_make_step "make check-x8664-churn" check-x8664-churn
    else
        printf '==> verify[%s]: skipping x86_64 runtime smoke (set RUN_X86_64_RUNTIME=1 to enable)\n' \
            "$VERIFY_TIER"
    fi
    if [ "$RUN_AARCH64_RUNTIME" = "1" ]; then
        run_make_step "make check-aarch64-runtime" check-aarch64-runtime
        # And the same device on the device-tree machine, where the BAR comes
        # through the platform's window instead of an address the firmware
        # assigned.
        run_make_step "make check-aarch64-nvme" check-aarch64-nvme
        # And audio on this machine: the same controller, now reached through
        # the ECAM window and a low BAR alias rather than the configuration
        # ports, with the host's WAV backend as the instrument again.
        run_make_step "make check-aarch64-hda" check-aarch64-hda
        # The same boot with the payload frozen rather than compiled, on the
        # architecture whose payload's entry point is not at its start.
        run_make_step "make check-abi-frozen-payload-aarch64" check-abi-frozen-payload-aarch64
    else
        printf '==> verify[%s]: skipping aarch64 runtime smoke (set RUN_AARCH64_RUNTIME=1 to enable)\n' \
            "$VERIFY_TIER"
    fi
    if [ "$RUN_RISCV64_RUNTIME" = "1" ]; then
        run_make_step "make check-riscv64-runtime" check-riscv64-runtime
        # And the same boot with the payload frozen rather than assembled, on
        # the architecture whose payload is hand-written assembly.
        run_make_step "make check-abi-frozen-payload-riscv64" check-abi-frozen-payload-riscv64
        # The RISC-V half of the same two fallbacks.
        run_make_step "make check-riscv64-churn" check-riscv64-churn
        # The AIA machine: the only boot that reaches the IMSIC, which is what
        # receives MSIs.  The PLIC machine above never touches that path.
        run_make_step "make check-riscv64-aia-runtime" check-riscv64-aia-runtime
        # And the machine where the APLIC has no IMSIC behind it: it used to
        # fault in a PLIC write at boot, and no gate booted it.
        run_make_step "make check-riscv64-aplic-direct-runtime" check-riscv64-aplic-direct-runtime
        # And the machine's PCIe window, which the device-tree parser used to
        # settle when it read `reg` — before `compatible` said the node *was* a
        # host bridge.  No boot had a PCIe device on the bus to notice.
        run_make_step "make check-riscv64-pci-runtime" check-riscv64-pci-runtime
        # And the device class beside the NIC, which is what needed this
        # machine's RAM window to be translatable for DMA.
        run_make_step "make check-riscv64-nvme" check-riscv64-nvme
    else
        printf '==> verify[%s]: skipping riscv64 runtime smoke (set RUN_RISCV64_RUNTIME=1 to enable)\n' \
            "$VERIFY_TIER"
    fi
    if [ "$RUN_SMP_RUNTIME" = "1" ]; then
        # The SMP smoke is meaningless on one CPU, and the Makefile's own
        # default is one because that is what `make run` should give a
        # developer.  Asking for the smoke therefore asks for four CPUs;
        # VERIFY_SMP overrides it.
        run_make_step "make check-smp-runtime" check-smp-runtime "SMP=${VERIFY_SMP:-4}"
        # The other two architectures' cross-CPU paths, which nothing else
        # boots: `check-smp-runtime` is x86_64, and the single-CPU smokes above
        # cannot reach a second CPU at all.
        run_make_step "make check-aarch64-smp-runtime" check-aarch64-smp-runtime "SMP=${VERIFY_SMP:-4}"
        run_make_step "make check-riscv64-smp-runtime" check-riscv64-smp-runtime "SMP=${VERIFY_SMP:-4}"
    else
        printf '==> verify[%s]: skipping SMP runtime smoke (set RUN_SMP_RUNTIME=1, and VERIFY_SMP for the CPU count, to enable)\n' \
            "$VERIFY_TIER"
    fi
}

case "$VERIFY_TIER" in
    p0) run_p0 ;;
    p1) run_p1 ;;
    p2) run_p2 ;;
    p3) run_p3 ;;
esac

printf 'verify[%s] complete\n' "$VERIFY_TIER"
