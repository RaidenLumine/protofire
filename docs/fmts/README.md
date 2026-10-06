# Contributor Specifications

This directory holds the normative specifications for contributing to the
Protofire kernel: how code is written, how it is commented, what `unsafe` may be
used for, how tests are laid out, and what the syscall ABI contract is.

They are written for anyone about to send a patch — a first-time contributor
looking for the house style, and a returning one checking whether a rule they
remember is real. [CONTRIBUTING.md](../../CONTRIBUTING.md) carries the short form
of all of this plus the process around it (setup, review, commits). These
documents are the detail behind those bullets: the rationale, the exact rules,
the cases that trip people up, and what is actually enforced versus what is
merely expected.

---

## The documents

| Document | Read it when | Covers |
|----------|--------------|--------|
| [code-style.md](code-style.md) | Writing any Rust in this repo | Formatting, naming, module and file layout, imports, visibility, error handling, globals, feature gating |
| [comments.md](comments.md) | Opening a file to edit it | The enforced file header, module and item docs, `# Safety`/`# Errors`/`# Panics`, section separators, `TODO`/`NOTE` |
| [unsafe-and-safety.md](unsafe-and-safety.md) | Writing or reviewing an `unsafe` block | What `unsafe` is for, the `// SAFETY:` contract, the ring-3 boundary, MMIO, locking and panic rules |
| [testing.md](testing.md) | Adding behaviour you want to keep | Unit vs. integration placement, registration, fault injection and property tests, what to test for a given change |
| [syscall-abi.md](syscall-abi.md) | Touching `src/abi/`, `src/syscall/`, or `src/user/shared/` | Append-only numbering, stability classes, versioning, pointer specs, the step-by-step procedure |
| [commits.md](commits.md) | Writing a commit message, or when the hook rejects one | Subject and body rules, type prefixes, the exact hook semantics, writing in Chinese, amend and fixup |

Supporting context, if you have not read it yet:

- [docs/kernel/README.md](../kernel/README.md) — how each subsystem works
- [docs/status.md](../status.md) — what is implemented, and the known gaps (a
  good source of work)
- [docs/rfcs/](../rfcs/README.md) — how a change too large for a pull request
  gets a design document, and the decisions those documents record

---

## What is enforced, and what is not

The single most useful thing to know before your first PR is which rules a
machine will check for you. Formatting, file headers, the documentation
citations, and a set of ratchets over `unsafe`, layering, architecture fan-out,
dead-code annotations, and the ABI mirror are all gated; the rest is review.

| Rule | Enforced by | Where it runs |
|------|-------------|---------------|
| Formatting | `make fmt-check` (`cargo fmt --all --check`) | `verify-p0`, CI |
| `.rs` file headers | `check_source_headers` in [`scripts/verify.sh`](../../scripts/verify.sh) | `verify-p0`, CI |
| Every file a document cites | [`scripts/check-docs.sh`](../../scripts/check-docs.sh) — `make check-docs`: `src/...` paths and relative links must resolve, bare filenames must exist somewhere, line-number citations are refused | `verify-p0`, CI |
| The RFC directory | [`scripts/check-rfcs.sh`](../../scripts/check-rfcs.sh) — `make check-rfcs`: four-digit decimal numbers, a status from the fixed set, supersede links that agree at both ends, and an index generated from the documents (`--record` rewrites it) | `verify-p0`, CI |
| Commit hook installed | `check_commit_hooks` in the same script | `verify-p0` |
| Commit message shape, `Signed-off-by:` | [`scripts/hooks/commit-msg`](../../scripts/hooks/commit-msg) — see [commits.md](commits.md) | Every `git commit` (`make install-hooks`), and every PR commit in CI |
| Lints | `make clippy` (`-D warnings`) and `make clippy-targets` (`-D warnings` for every target the tree builds for) | CI, `verify-p3` |
| Undocumented `unsafe` | `make clippy`, `make clippy-targets` (the lint is denied), and `make check-unsafe-comments` as a per-configuration census | `verify-p3`, CI |
| Syntax and types on every target | `make check` (host + x86_64 + the aarch64 host configuration), `make check-aarch64`, `make check-riscv64`, `make build`, `make build-aarch64` | `verify-p0` and `verify-p3`, CI |
| Module dependency edges | `make check-layering` against `scripts/layering-baseline.txt` | `verify-p3`, CI |
| Architecture `cfg` fan-out | `make check-arch-fanout` against `scripts/arch-fanout-baseline.txt` | `verify-p3`, CI |
| File-level `allow(dead_code)` | `make check-dead-code-allows`: the annotation must carry a reason and an exit condition | `verify-p3`, CI |
| Every configuration the manifest declares | `make check-feature-matrix`: each feature built in the shipped `demo-disk` configuration, and then all of them together; a feature that is not part of a kernel build is listed there with where it is built instead | `verify-p3`, CI |
| ABI records against their user-space mirror | `make check-abi-mirror` against `scripts/abi-mirror-baseline.txt` | `verify-p3`, CI |
| Repository object database | `make check-repo-integrity` (`git fsck`, with the benign notices filtered) | `verify-p0`, CI |
| **Everything else in this directory** | **Review** | — |

The rules in this directory that a machine does not check are the naming
conventions, doc-comment coverage, panic discipline, and the parts of the
syscall contract that are not a number or a record layout. Those are held up by
reviewers and by the tests that pin an invariant — a missing pointer-spec entry
fails the build, but a badly named function does not. Treat the unenforced rules
as *more* important to get right, not less: nothing will remind you.

### The verification gate

```bash
make verify           # default P3 gate
make verify-p0        # fmt + type checks + builds + source headers + hook check
make verify-p1        # p0 + host unit tests and fast regressions
make verify-p2        # p1 + storage / recovery / fault-matrix suites
make verify-p3        # p2 + clippy (all targets)
```

CI runs `make check`, `make verify-p0`, and `make clippy` on every push and pull
request, and validates every commit message on a PR. See
[testing.md §7](testing.md#7-running-tests) for the test coverage inside each
tier.

---

## Changing a specification

These documents are part of the codebase and change by pull request like
everything else.

- **If your change alters a convention, update the specification in the same
  PR.** A patch that starts naming things differently, or introduces a new
  comment marker, or moves where tests live, is incomplete until the rule
  document says so.
- **Do not quietly diverge.** If a rule here does not match what the code does,
  that is a defect in one of the two — raise it. A rule that deliberately
  describes the *direction* the code is moving rather than the current state of
  every file — the section separators, which older files under `src/arch/` still
  contradict — is called out where it occurs, so that "the file next door does
  it differently" is not a reason to copy it.
- **Prefer changing the code to weakening the rule.** A rule that exists because
  a class of bug is expensive in a kernel should be met with an argument, not an
  exception.

---

## Related documents

- [CONTRIBUTING.md](../../CONTRIBUTING.md) — setup, workflow, commit guidelines,
  review process
- [MAINTAINERS.md](../../MAINTAINERS.md) — who owns which subsystem
- [ROADMAP.md](../../ROADMAP.md) — the project's guiding principles
- [docs/kernel/](../kernel/README.md) — subsystem documentation
