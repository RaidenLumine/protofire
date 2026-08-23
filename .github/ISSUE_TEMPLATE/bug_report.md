---
name: Bug report
description: Report a defect — crash, hang, panic, or incorrect behaviour in the kernel, drivers, filesystem, network stack, or demo shell.
title: "[Bug] "
labels: ["bug"]
assignees: []
body:
  - type: markdown
    attributes:
      value: |
        Thanks for taking the time to fill out this bug report. Issues and PRs
        may be written in English or 简体中文.
  - type: textarea
    id: description
    attributes:
      label: Description
      description: What happened? What did you expect to happen?
      placeholder: A clear and concise description of the bug.
    validations:
      required: true
  - type: dropdown
    id: architecture
    attributes:
      label: Target architecture
      description: Which target did the bug occur on?
      multiple: true
      options:
        - x86_64
        - aarch64
        - riscv64
    validations:
      required: true
  - type: input
    id: environment
    attributes:
      label: Environment
      description: QEMU model & version, or real hardware. Include any relevant feature flags.
      placeholder: e.g. qemu-system-x86_64 9.0, --features demo-disk
    validations:
      required: true
  - type: textarea
    id: reproduction
    attributes:
      label: Steps to reproduce
      description: How do we reproduce this from a clean checkout?
      placeholder: |
        1. make verify-p3
        2. make run
        3. In the demo shell: ...
        4. Observe ...
    validations:
      required: true
  - type: textarea
    id: actual
    attributes:
      label: Expected vs. actual behaviour
      description: What did you expect, and what happened instead?
    validations:
      required: true
  - type: textarea
    id: logs
    attributes:
      label: Logs / backtrace
      description: Paste relevant serial output, panics, or a backtrace. Trim anything sensitive.
      render: shell
  - type: checkboxes
    id: verification
    attributes:
      label: Verification
      description: Helps us narrow down whether this is a regression.
      options:
        - label: "I can reproduce this on `main` at the latest commit."
        - label: "This worked before (please mention the last known-good commit below)."
        - label: "`make check` and `make clippy` pass locally."
  - type: textarea
    id: context
    attributes:
      label: Additional context
      description: Anything else that might help — related issues, hardware quirks, etc.
