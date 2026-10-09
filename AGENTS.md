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
ratchets.  `make help` lists every target, and `make check-make-targets` is what
keeps that true: the rules, `.PHONY` and the `help` recipe have to name the
same set, in both directions.

CI (`.github/workflows/ci.yml`) runs a subset of that tier on every push, so a
green CI is not the floor; the local `verify` is.  It is also where a citation
in this file is checked: `make check-docs` reads every Markdown file in the
tree, including this one, and refuses a path or a target the tree does not
have.

The ratchets decide whether a change can land, by what they hold still:
the dependency graph (`check-layering`, `check-arch-fanout`), memory safety
and what the code says about itself (`check-unsafe-comments`,
`check-user-access-windows`, `check-dead-code-allows`), the ABI
(`check-abi-mirror`, `check-abi-frozen-payload`, one per architecture), the
repository itself (`check-repo-integrity`, `check-reproducible-build`), and
the work a boot does (`check-perf-baseline`).  `docs/status.md` has one of its
own: `check-status-rows` refuses a census row that has grown past what a row
may be, because the story of what landed in a subsystem is the RFC's and the
mechanism is `docs/kernel/`'s.  Meeting that gate — or any other — by recording
a new number is a change that argues for it in the baseline's own prose.

Fast loops are `make run-x8664`, `run-aarch64` and `run-riscv64` (add
`-headless` to keep the serial console off the terminal); the smokes are
`check-x8664-runtime`, `check-aarch64-runtime` and `check-riscv64-runtime`,
plus the ones whose names end in `-smp-runtime` for the paths only a second
CPU reaches.

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
- **Say what evidence shows the mechanism ran, and name it.**  Quote the log
  line or the gate that shows it, so a reader can re-run it; the recurring
  defect here is code that is written, wired, and never executed, and a claim
  whose evidence cannot be re-checked is a claim, not a result.  A claim no
  gate exercises is "implemented", not "verified".
- **A red gate means the product is broken.**  Fix it, or make the failure
  attributable.  Never widen a gate, or loosen its tolerance, to go green.
- **A ratchet moves in the change that moves it.**  A raised count carries its
  argument in the baseline's own prose, the way `scripts/layering-baseline.txt`
  argues its exceptions.
- **One change per commit.**  A commit is the change and its gates and its
  documents, and nothing else: no drive-by refactor, no unrelated formatting,
  no second fix that merely happened to be nearby.  When two things really do
  have to move together, say why in the message.  (The commit-message rules
  themselves are `docs/fmts/commits.md`'s; this one is about the *shape* of a
  change, which no hook can see.)

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
