# Security Policy

[English](./SECURITY.md) | [简体中文](./SECURITY.zh-CN.md)

Protofire is a research-grade bare-metal kernel prototype. Security is taken
seriously: the kernel implements PAN/SMAP/SUM, the Biba integrity model, MAC
type enforcement, seccomp filtering, per-thread stack canaries, an audit
subsystem, and encryption at rest (AES-256-XTS + LUKS2). That said, this is a
research project — **do not run it with untrusted workloads in production**.

## Supported Versions

| Version | Supported |
|---------|-----------|
| `main` (development) | Active fixes |
| `1.0.x` (latest tagged release) | Security fixes & backports |
| Older releases | Not supported |

## Reporting a Vulnerability

**Please do not file a public issue for security vulnerabilities.**

To report a vulnerability privately:

1. **Preferred:** use GitHub's **private vulnerability reporting**
   (repository **Security** tab → **Report a vulnerability**). Only the
   maintainers can see the report.
2. **Fallback:** open a regular issue with the title prefix `SECURITY:`
   containing **no** exploit details, and we will reach out to you directly.

In your report, please include:

- The affected architecture (`x86_64` / `aarch64` / `riscv64`) and, if relevant,
  the affected feature flags.
- The environment (QEMU model & version, or real hardware).
- A minimal reproducer: boot command, kernel build flags, steps.
- Expected vs. observed behaviour, and any panic/log output.
- Your assessment of severity/impact, if you have one.

You will receive an acknowledgment **within 5 business days**, and progress
updates as the issue is triaged and fixed.

## Disclosure Policy

- We follow a **90-day coordinated disclosure** window: reporters are asked to
  withhold public details until a fix is available.
- Fixes land on `main` first, then are backported to the latest supported
  release (`1.0.x`).
- We will credit the reporter in the advisory unless anonymity is requested.

## Scope

**In scope:** the kernel source under `src/`, the build system (`Makefile`,
`build.rs`, linker scripts), and the user ABI implementation under
`src/user/shared/`.

**Out of scope:** host-side toolchains, QEMU itself, the host OS, and any
third-party crates not vendored in this repository.

## Bug Bounty

This project does not currently offer a bug bounty. We thank researchers for
their responsible disclosure in the interest of a better kernel.
