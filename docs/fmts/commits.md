# Commit Message Specification

> **Status:** normative.
> **Applies to:** every commit you push, and every commit in a pull request.

A commit message is the only part of a change that outlives every refactor of
the code it describes. The diff shows *what* changed and can be regenerated at
any time; the message records *why*, and it is the one artifact that cannot be
reconstructed afterwards. Rewriting it means rewriting published history, which
is why the rules here are worth getting right before the commit, not in review.

Commits are also unusual among the conventions in this directory in that they
are **fully machine-checked**. [`scripts/hooks/commit-msg`](../../scripts/hooks/commit-msg)
runs on every `git commit` and, from CI, on every commit in a pull request. This
document is the exact semantics of that hook, the places where it is easy to
trip over, and the parts of the convention it cannot see at all.

[CONTRIBUTING.md](../../CONTRIBUTING.md#commit-message-guidelines) carries the
short form. Read that first; read this when a commit is rejected, when you are
writing in a language other than English, or when you want to know whether a
rule is enforced or merely expected.

---

## 1. The subject line

```
<type>: <Imperative summary>
```

One line. The canonical shape is the type prefix, a colon, a space, and then a
summary of the change written as a command.

**Example:**

```
fix: Drop the extra ELR advance in aarch64 svc dispatch
```

The two halves of that summary — **imperative mood** and **capitalised first
word** — are both required, and together they produce a specific form that is
not the same as either habit people arrive with:

| Subject | Verdict |
|---------|---------|
| `fix: Drop the extra ELR advance …` | Correct — imperative and capitalised. |
| `fix: Dropped the extra ELR advance …` | Wrong — past tense. |
| `fix: drop the extra ELR advance …` | Wrong — not capitalised. |
| `fix: Drops the extra ELR advance …` | Wrong — third person. |
| `fix: Fixing the ELR advance …` | Wrong — gerund. |

Read the subject as the completion of the sentence *"This commit will…"*. It
will *drop* the ELR advance; it did not *drop* it, and it is not *dropping* it.

This is the most common error in this repository's own history. Of the commits
that use a type prefix, roughly 44 start lowercase and about 8 are capitalised
past tense — two different ways of missing the same rule. The rule is not
retroactive (published history stays as it is), but it applies to every new
commit.

Only the last two columns of the table are machine-checked; see §5.

### Subject rules

| Rule | Enforced by |
|------|-------------|
| A `<type>:` prefix | Review — see §2 |
| Imperative mood | Review |
| Capitalised first word | Review |
| At most 72 characters | The hook, for ASCII subjects only |
| No trailing period | The hook |
| No leading or trailing whitespace | The hook |
| Not a bare generic word | The hook |
| `Merge …` / `Revert …` are exempt from all of the above | The hook |

---

## 2. Type prefixes

Every commit carries a type. This is a rule, not a preference — 96% of the
commits in this repository's history already comply, and a specification that
described reality more loosely than the code would be the wrong way round.

| Type | Use for |
|------|---------|
| `feat:` | New user-visible behaviour or capability |
| `fix:` | A defect fix — a change that makes something broken work |
| `refactor:` | Restructuring with no intended change in behaviour |
| `chore:` | Build, tooling, dependencies, housekeeping; no behaviour change |
| `docs:` | Documentation only |
| `test:` | Tests only |
| `style:` | Formatting and whitespace only; no semantic change |

**Choose by what the change does, not by which file it touches.** A new test
that also fixes the bug it was written for is a `fix:`; a `Cargo.toml` edit that
changes compiled behaviour is not a `chore:`.

### Scope (optional)

A parenthesised scope narrows the area:

```
fix(ata): Drop the PIO timeout to the controller's minimum
docs(fmts): Describe the trailer exemption in the body-wrap check
```

Use the module or subsystem name — the same vocabulary as
[MAINTAINERS.md](../../MAINTAINERS.md). Scope is permitted but not required, and
no commit in the current history uses it; introduce it deliberately rather than
by habit.

### Release markers

The one exception to the required prefix is a release marker, which names the
version instead of a type:

```
Protofire 0.3.0
Protofire 0.1.1: Reuse the majority of the former unused constants
```

A release marker still obeys the length and trailing-period rules. The second
example above does not — it is 104 characters and ends in a period — and it is
one of the four commits in this history the hook rejects. Do not copy it.

---

## 3. The body

After the subject, a blank line, then prose.

- **Say why.** The diff already carries the *what* in more detail than prose
  can. What the reader cannot recover is the problem you were solving, the
  alternative you rejected, and the constraint that forced this shape.
- **Do not restate the diff** as a list of files, and do not narrate the
  obvious. Mention a file only where its involvement is not what a reader would
  expect.
- **Wrap at 72 characters.** `git log` indents the body by four columns, so 72
  is what fits an 80-column terminal.
- **Reference the issue** where one exists: `Fixes #123`.
- **One logical change per commit.** If the body is growing past a few lines,
  that is usually a signal that the commit is doing two things.

A body is optional in the sense that the hook does not require one. It is not
optional in the sense that matters: a subject alone is enough only when the
reason is genuinely self-evident, which is rarer than it feels at the time.

---

## 4. What the hook checks, exactly

`scripts/hooks/commit-msg` is a short `sh` script and is worth reading in full.
The order below is the order it executes; it reports the **first** failure and
exits, so a message with two problems needs two attempts to fix.

Before any check runs, every line whose first non-whitespace character is `#` is
**deleted** from the message (this strips the comment block `git commit` puts in
the editor template).

| # | Check | Failure message |
|---|-------|-----------------|
| 1 | A subject line exists | `empty subject line` |
| 2 | No leading/trailing whitespace on the subject | `subject must not have leading/trailing whitespace` |
| 3 | `Merge …` and `Revert …` subjects exit **0 here**, skipping every check below | — |
| 4 | The subject does not end in `.` | `subject must not end with a period` |
| 5 | The subject is not a bare generic word | `subject '<word>' carries no information` |
| 6 | The subject is at most 72 **bytes** — only if it is pure ASCII | `subject too long (N > 72 chars)` |
| 7 | Every body line is at most 72 characters | `body has lines over 72 chars` |
| 8 | `Signed-off-by:` appears somewhere in the message | `missing Signed-off-by trailer` |

### The traps

- **A body line starting with `#` is silently removed, not rejected.** The
  stripping in step 0 is meant for the editor template, but it cannot tell a
  template comment from your prose. `#123 is the root cause` disappears from the
  commit. Write `Fixes #123` or `Issue #123` instead.
- **`Merge` and `Revert` skip everything, including the signature check.** These
  subjects are generated by git and are exempt by design. The exemption covers
  the whole hook, so a `Revert …` commit is not required to be signed off.
- **A single non-ASCII byte exempts the subject from the length limit.** The
  check is a `LC_ALL=C` test for any byte outside `0x20`–`0x7E`, so an em dash, a
  curly quote, or an accented letter in the subject turns the limit off
  entirely. The exemption exists because a byte count is not a fair measure of
  CJK text (see §7), but it is not a licence to write a long subject.
- **The generic-word check is a fixed literal list**, matched against the whole
  subject:
  `update|Update|fix|Fix|fixup|cleanup|Cleanup|typo|wip|WIP|Wip`. With a type
  prefix required, it will rarely fire — `fix: …` is not the bare word `fix`.
  Note the list is inconsistent about case (`wip`, `WIP`, and `Wip` are all
  present; `UPDATE` and `Fixup` are not), so do not treat it as an exhaustive
  guard.
- **The body-wrap check exempts trailer-shaped lines.** A line matching
  `^[[:alpha:]][[:alnum:]_-]*:` is skipped, which is how `Signed-off-by:` stays
  on one line. It also means `Note: <a very long line>` escapes the check.
- **The subject is not re-checked for wrapping.** Step 7 starts at line 2; the
  subject is governed by step 6 alone.
- **Body length is counted in characters, not bytes**, so a CJK body line is
  measured fairly — unlike the subject check, which is byte-based and therefore
  waived for non-ASCII.

---

## 5. What the hook does not check

Everything here is a rule of this specification and none of it is machine
enforced. Following §3 of
[README.md](README.md#what-is-enforced-and-what-is-not), treat these as *more*
important to get right, because nothing will remind you:

- **The type prefix.** Not checked at all — `Add a thing` passes the hook.
- **Imperative mood and capitalisation.** The hook has no parser for English.
- **A body.** A bare subject with no body passes.
- **Anything about the trailers except that `Signed-off-by:` exists.** The hook
  cannot tell `Signed-off-by: Claude <noreply@anthropic.com>` from a person, so
  a commit that violates the DCO policy by having a tool sign passes cleanly.
  See [CONTRIBUTING.md](../../CONTRIBUTING.md#commit-message-guidelines) for the
  trailer policy and the fixed roles — people sign and co-author, tools assist.
- **Whether `Assisted-by:` is present** when a tool was involved, or whether its
  `AGENT:MODEL [TOOLS]` shape is right.
- **Trailer order.** Conventionally `Signed-off-by:` comes last, after
  `Co-authored-by:` and `Assisted-by:`.

Attribution trailers are exempt from the 72-character body wrap. Keep each on a
single line.

---

## 6. Attribution trailers

The trailer policy — which trailer names what, and the rule that the roles never
cross — is specified in
[CONTRIBUTING.md](../../CONTRIBUTING.md#commit-message-guidelines) and is not
duplicated here. The complete form for an AI-assisted commit:

```
Fix ATA timeouts on cold boot

Explain why, not what.

Signed-off-by: Ada Kernelson <ada@example.com>
Co-authored-by: Bob Lin <bob@example.com>
Assisted-by: Claude:claude-sonnet-4.5 coccinelle
```

`Signed-off-by:` is the only one the hook requires, and `git commit -s` adds it.
It is also the only one that must name a person.

---

## 7. Writing the message in Chinese

Issues and pull requests may be written in English or Simplified Chinese
([CONTRIBUTING.md](../../CONTRIBUTING.md#submitting-changes)), and the same
latitude applies to commit messages. No commit in the current history uses
Chinese, so this section is guidance rather than a description of practice.

**What does not change.** The message is still checked by the hook: it needs a
`Signed-off-by:` trailer, it must not have leading or trailing whitespace, and
it must not be a bare generic word. The type prefix still applies — it is ASCII
either way:

```
fix: 移除 aarch64 svc 分发中多余的 ELR 推进
```

**What changes.** The capitalisation half of §1 has no meaning in Chinese, so it
does not apply. Keep the imperative intent: write the bare verb phrase, not a
completed-aspect one. `移除多余的 ELR 推进` is the command form; `已移除多余的
ELR 推进` reads as a report of something already done, which is the same mistake
as the English past tense in §1.

**Length.** The 72-byte limit is waived when the subject contains non-ASCII
bytes, because a byte count cannot be compared against an ASCII column budget.
Keep the subject short anyway: `git log --oneline` truncates by display width,
and a CJK glyph occupies two columns, so the practical budget is roughly half
the number of characters you would use in English.

**The trailing-period rule is ASCII-only.** It matches a literal `.`, so a
subject ending in `。` passes the hook. Do not — the intent of the rule is that
the subject is a title, and the full stop of a Chinese sentence is a full stop.

---

## 8. Amend, fixup, and squash

CI does not validate only the tip of your branch. The `commit-message` job
resolves `git rev-list <base>..<head>` and pipes **every** commit in the pull
request through the hook individually. Consequences:

- **Every commit must stand on its own**, including fixups and work-in-progress
  commits you intend to squash later.
- **`git commit --amend` re-runs the hook.** This is the fix for a rejected
  message, and the reason the check being local matters: you find out at commit
  time, not in CI twenty minutes later.
- **`git commit --fixup=<sha>` needs `-s`.** The generated `fixup! <subject>`
  subject passes the checks on its own, but a fixup commit has no
  `Signed-off-by:` unless you ask for one:

  ```bash
  git commit --fixup=<sha> -s
  ```

- **Squashing happens at merge**, so a fixup's `fixup!` prefix never reaches the
  main branch — but it does reach CI, which is why it still has to pass.

---

## 9. Review checklist

- [ ] Subject is `<type>: <Imperative capitalised summary>` — `Add`, not `Adds`,
      `Added`, or `Adding`.
- [ ] The type matches what the change actually does.
- [ ] At most 72 characters, no trailing period, no leading/trailing space.
- [ ] The body says why, and would still make sense to a reader who has not seen
      the diff.
- [ ] No body line starts with `#`.
- [ ] `Signed-off-by:` present, naming a person — not a tool.
- [ ] `Assisted-by:` present if a tool was involved; no role crossing.
- [ ] `git log --oneline -1` reads as a sentence you would want to find later.

---

## Related documents

- [CONTRIBUTING.md](../../CONTRIBUTING.md#commit-message-guidelines) — the short
  form of these rules, the trailer policy, and the review process
- [docs/fmts/README.md](README.md) — which rules are enforced and which are not
- [docs/fmts/comments.md](comments.md) — the same question for the comments
  inside the change
