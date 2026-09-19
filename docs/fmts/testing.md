# Testing Specification

> **Status:** normative.
> **Applies to:** `tests/`, in-module `#[cfg(test)]` modules, and the test
> targets in [`Cargo.toml`](../../Cargo.toml) and the
> [`Makefile`](../../Makefile).

The project's guiding principles put correctness before features and require
that every milestone ends in tests. That is not a formality: a kernel has no
runtime to catch what a test misses. A bug in the TLSF allocator, the SimpleFs
undo log, or a page-table walk does not produce a failed request — it produces a
machine that stops.

Two facts shape how testing works here, and both are worth internalising before
writing your first test:

1. **Tests run on the host, not on the target.** The kernel targets are
   `#![no_std]` bare-metal; the test harness needs an OS to run in. So `tests/`
   is compiled for the host with `std`, linking the kernel crate as the
   `protofire` library. What that means in practice: most of the kernel is
   reachable and testable, but anything that depends on ring 0, on real
   hardware, or on an active user address space is not.
2. **Isolation is manual.** Integration tests that install globals are sharing
   process state with each other. Where a test installs a global singleton it
   must also uninstall it, or the next test in the binary inherits it — see §8.

---

## 1. Where tests live

| Kind | Location | Registered in |
|------|----------|---------------|
| **Unit** | `#[cfg(test)] mod tests` at the end of the module under test | Nothing to register |
| **Integration** | `tests/<area>/<name>.rs` | A `[[test]]` block in `Cargo.toml` |
| **Shared test helpers** | `tests/<area>/support/mod.rs`, or `src/**/test_support.rs` | `mod support;` in each consumer |
| **Fuzz harnesses** | `tests/{net,syscall,parsers}/fuzz.rs` | A `[[test]]` block |

There are around 300 `#[cfg(test)]` modules in `src/` and 25 integration test
binaries in `tests/`. Both kinds are expected for a new subsystem.

### Registration is not automatic

`Cargo.toml` declares every integration test explicitly:

```toml
[[test]]
name = "simplefs_fault_matrix"
path = "tests/simplefs/fault_matrix.rs"
```

Cargo does **not** auto-discover test files in subdirectories of `tests/`. A new
integration test that is not declared here will never run — and will never fail,
which is worse. Adding the `[[test]]` block is part of the change.

Then wire it into the Makefile if it belongs to a fast subset: `test-fast`,
`test-concurrency`, `test-storage`, or one of the focused targets. A test that
is not reachable from a `make` target is equally invisible in day-to-day work.

---

## 2. Unit tests

Unit tests live in a `#[cfg(test)] mod tests` block at the **end** of the file
they test — after the implementation, never in a separate file.

```rust
#[cfg(test)]
mod tests {
    use super::copy_user_bytes;
    use super::validate_user_input_buffer;
    use super::FixedOutputBuffer;

    #[test]
    fn validate_user_input_buffer_rejects_range_straddling_user_kernel_boundary() {
        // Start valid, end in kernel half — must be rejected.
        assert_eq!(
            validate_user_input_buffer((USER_ADDRESS_MAX - 3) as *const u8, 8, 8),
            Err(Error::InvalidArgument)
        );
    }
}
```

Conventions:

- **Name the behaviour, not the function.** Test names in this tree read as
  sentences about observable behaviour —
  `validate_user_input_buffer_rejects_range_straddling_user_kernel_boundary`,
  `percpu_size_is_cache_line`, `select_victim_returns_none_when_no_processes`.
  A name like `test_read_2` tells a reader nothing when it fails in CI at 2 a.m.
- **Import what you need explicitly, or `use super::*;`.** Both appear; roughly
  170 modules use the glob. Reach for explicit imports when the module under
  test has a large surface, and the glob when the test module exercises most of
  it. What you should not do is `use crate::…` to reach past the parent.
- **Test the boundaries and the rejections.** For anything taking a range, a
  length, or a pointer, the interesting cases are the edges: zero length, the
  last valid address, a range that straddles the user/kernel boundary, an
  argument index out of range. The syscall handler tests are a good model — they
  assert on `Err(Error::InvalidArgument)` as often as on success.

---

## 3. Integration tests

Integration tests exercise a subsystem through its public surface. They are
grouped by area under `tests/`: `fs/`, `io/`, `memory/`, `net/`, `process/`,
`sync/`, `syscall/`, `simplefs/`, `drivers/`, `gpu/`, `parsers/`.

```rust
//! tests/simplefs/fault_matrix.rs
//!
//! Exercise a block-level fault-injection matrix for writable SimpleFs recovery
//! behavior.

mod support;

use std::sync::Arc;

use protofire::kernel::fs::block::BlockDevice;
use protofire::kernel::fs::simplefs::SimpleFs;
use protofire::Error;
use protofire::Result;
```

- **The file header follows the same `//! <path>` rule** as `src/`, and
  `make verify-p0` checks it there too.
- **These tests may use `std`** — `Vec`, `HashMap`, `Arc`, `Mutex` from the host
  are all available and are the normal tools for building fixtures.
- **Import through `protofire::…`**, never by path into the crate's internals.
  If a test needs something that is not reachable, that is a signal about the
  API's visibility, not a reason to add a `pub` for the test's sake.
- **Shared helpers go in `support/mod.rs`** and are pulled in with
  `mod support;`. Keep a support module free of test cases of its own — it is a
  library for the tests beside it.

---

## 4. Test support in the kernel crate

When host tests need builder functions from inside `src/`, add them to a
`test_support` module and gate it:

```rust
#[cfg(any(test, feature = "demo-disk"))]
pub(crate) mod test_support;
```

`src/kernel/fs/test_support.rs` and `src/kernel/syscall/test_support.rs` follow
this shape. The `demo-disk` arm matters because the integration tests are built
with `--features demo-disk` and need the same helpers a unit test does.

Test support is `pub(crate)` — it exists for the crate's own tests, not as
public API, and it must not become the place a real feature is prototyped
because it is the only gated module available.

---

## 5. Robustness testing: fault injection and property tests

Behavioural tests check that the happy path works. For the storage stack, that
is not where the bugs are. The `tests/simplefs/` suite is the model for the
harder question, and new work in a transactional or recovery-bearing subsystem
is expected to follow it:

| Technique | File | What it does |
|-----------|------|--------------|
| **Validation** | `tests/simplefs/validation.rs` | On-disk format and consistency rules |
| **Fault matrix** | `tests/simplefs/fault_matrix.rs` | Injects block-level faults across the write path and checks that recovery restores a consistent state |
| **Recovery** | `tests/simplefs/recovery.rs` | Tears down mid-transaction and re-mounts |
| **Property** | `tests/simplefs/property.rs` | Randomised operation sequences checked against invariants |
| **Undo-log property** | `tests/simplefs/undo_property.rs` | Crash-point property tests for the undo log |

Two properties of this style are worth copying:

- **Enumerate the crash points, do not sample them.** A fault-injection test
  should be able to name every point at which an operation can be interrupted,
  and assert that each one recovers.
- **Make a failing seed reproducible.** When a property test finds a
  counterexample, it must report the seed or the operation sequence so the case
  can be replayed and then added as a fixed regression.

A property test that can pass vacuously — one whose generator never produces the
interesting case — is a known hazard here; there is a commit in the history
about hardening exactly that. Assert that the generator actually produced the
conditions you meant to test.

---

## 6. Fuzz harnesses

`tests/net/fuzz.rs`, `tests/syscall/fuzz.rs`, and `tests/parsers/fuzz.rs` are
**deterministic in-tree fuzz harnesses**, not libFuzzer targets: each uses a
small local PRNG seeded per test so a failure is reproducible in CI without a
corpus.

The contract they assert is narrow and valuable: **malformed input produces a
clean `Error`, never a panic, a hang, or undefined behaviour.** Feed the parser
or handler random and edge-case arguments and assert the result is an `Err`.

If you add or change a parser, a wire format, or a syscall argument layout, add
cases here. Note the caveat documented in the syscall harness: on the host there
is no active user address space, so passing a plausible-looking pointer (such as
`0x1000`) to a handler that dereferences it will segfault the test binary. The
harness deliberately restricts itself to `ptr = 0` and `ptr = usize::MAX`, which
hit the null and bounds checks before any dereference. Keep to that rule.

---

## 7. Running tests

```bash
make test              # host unit + integration, with demo-disk
make test-lib          # library unit tests only
make test-fast         # path, I/O, syscall, user integration
make test-concurrency  # scheduler, input, condvar
make test-storage      # filesystem, recovery, fault injection
make test-parsers      # deterministic parser fuzz harnesses
make test-usb          # USB mass storage
make test-gpu          # VIRGL renderer
```

Most integration tests need `--features demo-disk` so the in-memory demo volumes
exist; the Makefile passes it for you. If you invoke `cargo test` directly, match
the target: `cargo test --features demo-disk`.

### What the gate runs

| Gate | Test content |
|------|--------------|
| `verify-p0` | No tests — format, type checks, builds, source headers |
| `verify-p1` | `test-lib`, concurrency, and fast regressions |
| `verify-p2` | p1 + the storage/recovery/fault-matrix suites |
| `verify-p3` | p2 + clippy (this is what `make verify` runs by default) |

CI runs `make check`, `make verify-p0`, and `make clippy` on every push and pull
request; the deeper tiers are expected to be run locally for behavioural
changes. A storage or allocator change that has not been through `make
test-storage` has not been tested.

### Kernel behaviour needs a boot, not just a test

For a change to kernel behaviour, run the demo-disk shell under QEMU on the
affected architecture. The host tests cannot see the boot path, the trap path,
or anything that requires a real page table:

```bash
make run             # x86_64
make run-aarch64
make run-riscv64
```

All three are pure serial sessions (`-serial stdio`, no display device) and
reach an interactive ring-3 shell.

---

## 8. Isolation and globals

Integration tests in the same binary share a process. A test that installs a
global singleton without tearing it down will affect every test that runs after
it — producing a failure whose cause is in a different function entirely.

The rule: **if a test installs a global, it uninstalls it.** The install pattern
in [code-style.md §8](code-style.md#8-globals-the-install-pattern) exists partly
for this — most subsystems provide an `uninstall_global`, and `Drop` clears the
slot automatically. Prefer a fresh install/uninstall pair over assuming a
previous test left the state you want.

---

## 9. What to test

A short map from change to expected coverage. The right-hand column is a floor,
not a ceiling.

| You changed | Add or extend |
|-------------|---------------|
| A syscall (new or modified) | Manifest tests, handler unit tests, `tests/syscall/` coverage, fuzz cases for the new argument layout. See [syscall-abi.md §9](syscall-abi.md#9-tests). |
| A parser or wire format | Unit tests for valid/truncated/oversized input, plus `tests/parsers/fuzz.rs` |
| A filesystem | `tests/<fs>/` suite; for a writable one, a recovery or fault-matrix case |
| The allocator or paging | `tests/memory/` — `manager.rs`, `page_table.rs`, `pressure.rs` |
| The scheduler | `tests/process/scheduler.rs`, `stress.rs`; a concurrency case if wake order changes |
| A lock or wait queue | `tests/sync/condvar.rs` |
| A driver | A host-side test where the logic is separable from the hardware; a QEMU boot otherwise |
| A user-visible behaviour | An integration test under `tests/` that exercises it end to end |

---

## 10. Review checklist

- [ ] New behaviour has a test; the test fails before the fix and passes after.
- [ ] The test name describes the behaviour being asserted.
- [ ] Boundary, rejection, and error cases are covered, not just the happy path.
- [ ] New integration tests are registered with a `[[test]]` block **and**
      reachable from a Makefile target.
- [ ] The test file carries a valid `//! <path>` header.
- [ ] Tests that install a global uninstall it.
- [ ] No test passes vacuously — assert that the fixture produced the intended
      condition.
- [ ] `make test` and the relevant focused target are green.
- [ ] For kernel-behaviour changes, the demo-disk shell was booted on the
      affected architecture.

---

## Related documents

- [docs/fmts/code-style.md](code-style.md) — the global install pattern
- [docs/fmts/syscall-abi.md](syscall-abi.md) — syscall-specific test layers
- [docs/kernel-introduction/current-status.md](../kernel-introduction/current-status.md)
  — known gaps, a good source of work that needs tests
- [CONTRIBUTING.md](../../CONTRIBUTING.md) — the verification gate
