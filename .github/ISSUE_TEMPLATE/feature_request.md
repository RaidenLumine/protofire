---
name: Feature request
description: Suggest a new feature or improvement for the kernel, drivers, filesystem, network stack, demo shell, or docs.
title: "[Feature] "
labels: ["enhancement"]
assignees: []
body:
  - type: markdown
    attributes:
      value: |
        Thanks for suggesting a feature. Issues and PRs may be written in
        English or 简体中文. Before opening, please check
        [ROADMAP.md](../../ROADMAP.md) and the docs in [`docs/`](../../docs/)
        to avoid duplicates.
  - type: textarea
    id: motivation
    attributes:
      label: Motivation
      description: What problem does this feature solve, and why is it worth building?
      placeholder: A clear statement of the problem and the use case.
    validations:
      required: true
  - type: textarea
    id: proposal
    attributes:
      label: Proposed change
      description: What should the feature look like? Sketch the behaviour or API if relevant.
    validations:
      required: true
  - type: textarea
    id: alternatives
    attributes:
      label: Alternatives considered
      description: What else did you consider, and why is the proposal better?
  - type: dropdown
    id: scope
    attributes:
      label: Scope
      description: Where does this belong?
      multiple: true
      options:
        - Kernel core (scheduler / memory / VFS / syscall)
        - Drivers (block / net / gpu / usb / audio)
        - Network stack
        - Filesystem
        - Demo shell & user runtime (src/user/shared)
        - Architecture support
        - Documentation
    validations:
      required: true
  - type: input
    id: targets
    attributes:
      label: Affected targets
      description: Which architectures should this cover?
      placeholder: e.g. x86_64 + aarch64 (hardware permitting)
  - type: textarea
    id: context
    attributes:
      label: Additional context
      description: Links to related issues, RFCs, or design notes.
