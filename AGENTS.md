# Protofire — working rules

A `no_std` bare-metal kernel for x86_64, aarch64 and riscv64.  There is no
package ecosystem to consult and no upstream to imitate: the tree is the whole
world, and every instruction below is load-bearing.

**A rule that can be a gate belongs in a gate, not here.**  What follows is
either something no gate can express or a pointer to the gate that already
expresses it.  When one of these becomes mechanical, delete it from this file:
a healthy `AGENTS.md` gets shorter as the gates get stronger.

## Where the truth lives

| Question | Document |
| --- | --- |
| How does a subsystem work? | `docs/kernel/`, from its README |
| What was decided, and why? | `docs/rfcs/` |
| What exists, and what is missing? | `docs/status.md` |
| What must a contributor follow? | `docs/fmts/`, from its README |
| Where is this going? | `ROADMAP.md` |

The tree is the authority: where a document and the code disagree, the code is
right and the document is the bug.  Moving the document is part of the change,
not a follow-up — a behaviour change moves `docs/status.md`, and the status of
the RFC that decided it, in the same commit.

## Gates

The floor is `make verify VERIFY_TIER=p3`: the host suites, clippy in every
configuration (`make clippy`, `make clippy-targets`), the build matrix, a
single-CPU runtime smoke per architecture plus the multi-CPU one, and the
ratchets.  `make help` lists every target.

The ratchets decide whether a change can land: `check-layering`,
`check-arch-fanout`, `check-unsafe-comments`, `check-dead-code-allows`,
`check-abi-mirror`, `check-abi-frozen-payload` (and its per-architecture
variants), `check-repo-integrity`, `check-reproducible-build`,
`check-perf-baseline`, `check-user-access-windows`.

Fast loops are `make run-x8664`, `run-aarch64` and `run-riscv64` (add
`-headless` to keep the serial console off the terminal); the smokes are
`make check-<arch>-runtime`, plus the ones whose names end in `-smp-runtime`
for the paths only a second CPU reaches.

## Rules no gate can check

- **Verify before you replace.**  A change lands only with the gates green; an
  attempt that failed is reverted in the same session, and nothing exploratory
  stays in the tree.
- **One boot, one log.**  Read conclusions out of a single boot's log; never
  reason across builds.
- **A probe that did not fire is zero information**, unless that run
  reproduced the bug.  Measure the reproduction rate (N of M) before and after
  a fix, and keep probes off the hot path — they perturb exactly what they are
  looking for.  When the bug is timing-sensitive, instrument from outside
  (QEMU's monitor, a serial socket).
- **Say what evidence shows the mechanism ran.**  The recurring defect here is
  code that is written, wired, and never executed: a claim no gate exercises
  is "implemented", not "verified".
- **A red gate means the product is broken.**  Fix it, or make the failure
  attributable.  Never widen a gate, or loosen its tolerance, to go green.
- **A ratchet moves in the change that moves it.**  A raised count carries its
  argument in the baseline's own prose, the way `scripts/layering-baseline.txt`
  argues its exceptions.

## Boundaries

✅ **Always**: run `make fmt-check` before committing; end the message with
`Signed-off-by:` and then `Assisted-by:` (the order, and what each trailer is
for, are in `docs/fmts/commits.md`); write the safety argument at the `unsafe`
block it belongs to; keep a change's code, its gates and its documents in one
commit.

⚠️ **Ask first**: changing or renumbering the frozen syscall range (`0..=120`,
`docs/fmts/syscall-abi.md`); raising any ratchet baseline; editing `docs/fmts/`,
which is what other code is written against; touching the address-space
activation path, or anything else `docs/status.md` records as deliberate.

🚫 **Never**: `git reset --hard`, or `git checkout -- <path>`, over work that is
not yours; leave probe, `TEMPORARY` or debug code in a commit; commit with a
gate red; add a file-level `#![allow(dead_code)]` without the condition that
removes it; write `unsafe` without its argument.
