# Protofire RFCs

An RFC is a design document for a change that is too large to argue inside a
pull request: it states the problem, the options that were really considered,
the decision, and what would show the decision was wrong.  This directory is
where those documents live, and this file is the process that produces them.

The code remains the source of truth about *what exists* —
[docs/kernel-introduction/current-status.md](../kernel-introduction/current-status.md)
is the summary of that.  An RFC is the record of *what was decided and why*,
including the options that were not taken, which no amount of reading the
final diff can recover.

---

## When one is required

Write one, before the code, when a change would:

- add or change an interface between subsystems that other code will build
  on — the shape a driver, a filesystem, or a scheduler hands to its
  consumers;
- start a new subsystem, or a new machine or bus path under `src/arch/`;
- change a format that outlives a boot: on-disk, on-wire, or the syscall ABI
  beyond what [docs/fmts/syscall-abi.md](../fmts/syscall-abi.md) already
  fixes;
- change a policy a document states as settled, including a design decision
  [current-status.md](../kernel-introduction/current-status.md) records as
  deliberate;
- need more than one pull request to land.

It is not required — and is usually a wasted document — for a bug fix, a new
driver that fits an interface that already exists, a test, a ratchet
re-record, or an edit to prose.  When in doubt, open an issue first: an issue
is where an idea is allowed to be unfinished, and an RFC is where it stops
being.

## Lifecycle and status

Every RFC opens with a status line, and the status is the first thing a
reader looks at:

| Status | Means |
|--------|-------|
| **Draft** | Written and under discussion; not a decision |
| **Proposed** | Ready for a decision; the pull request that carries it is open |
| **Accepted** | Decided. Code that implements it refers back to it |
| **Implemented** | The code is in the tree; the document now records why |
| **Superseded** | Replaced by a later RFC, which is named in its header |
| **Rejected** | Considered and not taken, with the reason kept |

A merged RFC is a record, not a wiki page.  It gets edited for typos and for
its status moving as the code lands, but a change of decision is a new RFC
that supersedes the old one.  The old document stays: "we thought about this
and chose otherwise" is information, and deleting it would be the same
mistake as deleting a failing test.

## Numbering and layout

Files are `docs/rfcs/NNNN-short-title.md`, numbered in the order they are
accepted, starting at `0001`.  A number is never reused, not even after a
rejection.  [`0000-template.md`](0000-template.md) is not an RFC and is not
numbered.

`NNNN` is four **decimal** digits, zero-padded: `0009` is nine and `0010` is
ten, and no file ever carries a letter.  The padding is what makes the
directory's order (`ls`, `sort`, a diff) equal to the numeric order.  Numbers
are global and monotonic, so a skipped number stays skipped; if the project
ever outgrows four digits, new files take five and the old names stay where
they are.

Two mechanical facts about this directory are checked by
[`scripts/check-rfcs.sh`](../../scripts/check-rfcs.sh) (`make check-rfcs`):
those numbers, and the statuses below.  It also generates the index from the
documents themselves, so a document's status and the table that lists it
cannot drift apart — `--record` is how the table is written after a status
moves.

## Writing one

Copy the template and fill it in.  Its sections exist because a design that
cannot answer them is not finished; if one genuinely does not apply, delete
it and say why rather than leaving it empty.

Keep the document about the decision, not about the code that will implement
it — the diff is the diff.  Cite files by name so a reader can find the
current shape, and remember that `make check-docs` checks this directory like
any other document: a citation that names a file the tree does not have is a
failed build, not a typo.

## Reviewing one

An RFC is reviewed like a pull request, and the review is about the design:
what the options really are, which one the evidence supports, and what would
show the choice was wrong to make.  The maintainers who accept it are the
ones [MAINTAINERS.md](../../MAINTAINERS.md) names for the subsystems it
touches, with the core maintainer deciding when they disagree.

Today the project has one core maintainer, so acceptance is theirs; the rule
is written for the shape the roadmap is working toward, and a second
maintainer changes who answers, not what the answer has to say.

Accepting a design and implementing it are separate acts.  An RFC that is
accepted and then never built is still a decision the next person can read,
and its status says which of the two happened.

## The documents

<!-- rfcs-table:start -->
| RFC | Status | Subject |
|-----|--------|---------|
| [0001](0001-spread-message-signalled-interrupts.md) | Implemented | Deliver message-signalled interrupts on more than one CPU |
| [0002](0002-signal-frame-carries-the-context.md) | Implemented | Carry the interrupted context in the signal frame |
<!-- rfcs-table:end -->

The table is generated from the documents between the two markers above —
each document's own status line is the authority, and `scripts/check-rfcs.sh`
is what keeps the table saying the same thing.
