# fixtures/acpi — captured firmware tables

The tables here were **not** produced by this tree.  They were copied out of
a real machine's firmware, once, and checked in so a parser gate can run on
a shape no emulator describes.  A file in this directory is evidence about a
machine that existed; do not edit one, and do not regenerate an old one in
place — a new capture is a new file with the machine named.

## How to capture

`/sys/firmware/acpi/tables/*` is readable by root alone, which is why this
is a recipe rather than something a build can do:

```sh
sudo cp /sys/firmware/acpi/tables/APIC fixtures/acpi/APIC
```

The file that has mattered so far is `APIC` — the MADT, which names the
processors.  What it carries that QEMU's machines never do is the reason it
is here: real firmware describes every *possible* processor and switches the
absent ones off, so a machine with twelve cores writes thirty-two entries
and marks twenty disabled with APIC ID `0xff`; it also emits an IOAPIC
entry, interrupt-source overrides and one NMI entry *per processor*.  A
parser that mistook a placeholder for a processor, or that stopped at the
first entry type it did not know, would read a real board wrong and every
gate in this tree would still pass.

Other tables are welcome the same way when a parser for them exists — `SRAT`
and `SLIT` for the NUMA walk, `MCFG` for the PCIe window — one capture per
machine, the same recipe, and the tests that read them say which machine the
bytes came from.

## What reads them

`src/arch/x86_64/acpi.rs`'s unit tests: `parse_madt_bytes` is a pure
function over a table's bytes, and these tests run it on `APIC` and on
malformed tables (short, truncated, an entry that runs past the end), where
the only acceptable answers are a clean parse or an empty one — never a
panic and never a read past the slice.  The RSDT walk is driven the same
way: `rsdt_walk_finds_the_valid_table_behind_a_decoy` builds a synthetic
root whose entries are the captured table, a decoy that spells `APIC` with
a broken checksum and a candidate with a wild length, over a space whose
offsets are the addresses — so the walk's bounds, gate, signature and
checksum all run on a host.
