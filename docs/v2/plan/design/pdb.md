---
status: plan
summary: The smallest PDB that gives a Windows program named backtraces (std's dbghelp `SymFromAddr`), `file:line` frames and line breakpoints in cdb and Visual Studio - an MSF 7.0 file of the PDB info stream (the image's RSDS GUID and age), empty TPI and IPI, a DBI stream with one module per crate and the section headers, each module's `S_GPROC32` procedures and C13 line tables from the rows the ELF and Mach-O writers' `.debug_line` comes from, and publics with their hash. No types, parameters or locals. Written whole by each link first; patched per module later. Not built.
date: 2026-11-13
---
# PDB for blaze's PE images

blaze-link names a PDB in each image's debug directory (`pe/image.rs` `debug`, a CodeView
`RSDS` record of the image's GUID, age 1, `<stem>.pdb`) and writes none. So std's backtrace
(dbghelp) prints `<unknown>` for every frame, and cdb and Visual Studio show no function
names or lines. rustc's link writes a 399 MB PDB for rune-desktop. link.exe spends most of
its 7.2 s link of that line writing it.

## What is needed, and nothing more

| Consumer | Reads | So the PDB needs |
|---|---|---|
| std's backtrace (`dbghelp!SymFromAddr`, `SymGetLineFromAddr64`) | the publics, or the module's procedures, then the module's line table | publics, DBI module info, section map, section headers, C13 lines |
| cdb `k`, `bp file:line` | the same, plus `/names` for the file names | the `/names` stream and the checksums subsection |
| Visual Studio | the same; types for locals | types are out of scope |

Out of scope: types (TPI holds none; procedures say type 0), parameters and locals
(`S_LOCAL`, `S_DEFRANGE*`), inline sites (`S_INLINESITE`: a later step, from
`CompiledFunction.inlined`), and the C objects' own `.debug$S` (dropped today; a later step
merges them as modules of their own).

## Layout

An MSF 7.0 file of 4 KiB blocks: the superblock, two free-block maps, the stream directory
and the streams.

1. **Old directory** (stream 0): empty.
2. **PDB info** (stream 1): version 20000404, the signature (the image's time stamp), age 1,
   the GUID of the image's `RSDS` record, the named-stream map with `/names`, and the feature
   code `VC140`.
3. **TPI** (2) and **IPI** (4): a header with no records.
4. **DBI** (3):
   - the header;
   - one module per crate the image links (and one for what no crate names: the linker's
     thunks, the jump table), each with its section contribution;
   - the section contributions, sorted;
   - the section map;
   - the file info (each module's source files, as offsets into `/names`);
   - the optional debug header, whose section-header entry names a stream holding the
     image's section headers (dbghelp maps an RVA to a section and offset with it).
5. **One stream per module**:
   - signature 4 (C13);
   - for each function, `S_GPROC32` (name, section, offset, length, type 0), `S_FRAMEPROC`,
     `S_END`;
   - then the C13 subsections: `DEBUG_S_FILECHKSMS` (file names, no checksum) and one
     `DEBUG_S_LINES` per function, its rows from `CompiledFunction.lines` with the positions
     the span tables give (`position.rs`). These are the rows `dwarf.rs` turns into
     `.debug_line` for ELF and Mach-O, so one source of truth feeds both.
6. **Publics** (`S_PUB32`, function flag) and the GSI hash records and buckets; **globals**,
   an empty GSI.
7. **`/names`**: the string table of file names.
8. **Section headers**: a copy of the image's.

`crates/hir-ty-codegen/debuginfo/codeview.rs` (v1's) has the C13 line encoding. It moves
into `crates/blaze-link/src/pe/pdb.rs` with the MSF writer, since the linker owns the
addresses.

## Cost and incrementality

- **First link.** The PDB is written whole: about 60 bytes of procedure, public and hash per
  function plus about 8 bytes per line row. For rune-desktop's scale (say 400,000 functions
  and 4 M rows) that is about 60 MB, against rustc's 399 MB, which carries types. Blocks are
  written in parallel, one module a task.
- **An edit.** It changes a few functions of one module. Each module's stream gets room to
  grow, as the image's regions do. The patch rewrites:
  - that module's blocks;
  - the publics of the names that moved;
  - the section contribution entry, if the module's extent changed;
  - the stream directory block.

  That is the 4.3.2 design of the plan. It is a later step: the first build writes the file
  whole on each link, and the span `link pdb` measures it.

## Tests

- **Round trip.** `llvm-pdbutil dump -all` of a linked image's PDB reads every stream, and
  its modules, publics and lines match what was linked.
- **Run.** A run-tier program (`pe_run.rs`) with a Rust-compiled function panics, and its
  backtrace names the function and its `file:line`. `cdb -c "bp file:line; g; k"` stops
  there and names the frame. `harness/debuginfo.py`'s Windows path checks the same.
- **Determinism.** Two links of one input make the same bytes.
