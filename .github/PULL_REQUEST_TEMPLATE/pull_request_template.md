<!-- Thanks for contributing to Protofire! Please fill in the sections below and
     complete the checklist. Issues and PRs may be written in English or 简体中文. -->

## Summary

<!-- What does this PR do, in one or two sentences? -->

## Motivation

<!-- Why is this change needed? Reference issue numbers where applicable, e.g. "Fixes #123". -->

## Changes

<!-- Bullet-point the notable changes. For syscall ABI changes, list the
     numbers and whether they are Stable (0–120) or Experimental (121–189). -->

- 

## Testing

<!-- Which verification gates did you run? For kernel-behaviour changes, also
     boot the demo-disk shell under QEMU on the affected architecture. -->

- [ ] `make check`
- [ ] `make clippy`
- [ ] `make verify-p3` (or explain which tier you ran and why)
- [ ] QEMU demo-disk boot on: x86_64 / aarch64 / riscv64
- [ ] Tests added/updated: `tests/`, unit tests in-module

## Documentation

- [ ] Docs updated in both `docs/en/` and `docs/zh-CN/` (where applicable)
- [ ] `docs/<lang>/current-status.md` reflects the change

## Checklist

- [ ] One logical change per PR
- [ ] Code follows the project style (`cargo fmt`, `unsafe` blocks carry `// SAFETY:`)
- [ ] No new `#![no_std]` violations, no `panic!` in core paths
- [ ] No breaking syscall-number changes (append-only numbering respected)
