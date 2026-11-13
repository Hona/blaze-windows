---
status: plan
summary: A PE image's PDB is its side file - MSF 7.0 with the PDB info stream (the image's build id as GUID, age 1), empty TPI and IPI, DBI with one module of every Rust function, its section contributions, section map, files and the image's section headers, the module's `S_GPROC32` procedures and C13 line tables, publics for Rust and native functions, globals - giving std's backtrace (dbghelp) names and lines and cdb breakpoints by name. Built - the whole file per link (`pe/pdb.rs`, run-tier test through dbghelp; 400,000 functions in 0.30 s, 174 MB). Not built - patching it per function (this doc's second half), types, locals, inline sites, the C objects' own `.debug$S`.
date: 2026-11-13
---
# PDB for blaze's PE images

A PE image names its PDB in its debug directory (`pe/image.rs` `debug`): a CodeView `RSDS`
record of the image's build id, age 1, `<stem>.pdb`. The PDB is the image's side file
(`crate::beside`, [debug-side-file.md](debug-side-file.md)): `Image::debug_file` makes it and
blaze-cargo places it beside the image. rustc's link writes a 399 MB PDB for rune-desktop,
most of it types; link.exe spends most of its 7.2 s link of that line writing it.

## What is in it

| Consumer | Reads | So the PDB has |
|---|---|---|
| std's backtrace (`dbghelp!SymFromAddr`, `SymGetLineFromAddr64`) | the module a section contribution names, its procedures and line tables; publics where no module has the address | DBI, the module stream, publics |
| cdb `k`, `bp name`, `bp file:line` | the same, publics for names | the same, `/names` |
| Visual Studio | the same; types for locals | types are out of scope |

The streams, at fixed numbers (`pe/pdb.rs`): the PDB info stream (always block 3, so the build
id is at a fixed place, which `beside::id_of` reads), TPI and IPI with no records (procedures
say type 0) and their empty hash streams, DBI, `/names`, globals (an `S_PROCREF` per
procedure), publics (an `S_PUB32` per Rust and native function, the GSI hash, the address
map), the symbol record stream, the image's section headers, and one module, `blaze`:
`S_OBJNAME`, `S_COMPILE3` (Rust, x64), an `S_GPROC32` and `S_END` per function, then the C13
subsections, its files and a line table per function. The rows are the ones the ELF and
Mach-O side files' `.debug_line` is made of (`Image::debug_file`'s views), so one source feeds
every format. Native functions are publics named as their objects name them
(`native::Resolved::native_functions`); their own `.debug$S` is dropped.

Out of scope: types and locals, inline sites (from `CompiledFunction.inlined`, later), a module
per crate.

## Cost, written whole

Measured (`pe::pdb::tests::a_desktop_sized_pdb`, release, adais): 400,000 functions of 10 rows
in 2,000 files, with names as long as rustc's v0 names, take 0.30 s and make 174 MB. Per
function that is about 420 bytes: the name three times (procedure, public, reference), the
procedure, the line table, the hashes and the address map. The desktop's rustc objects linked
as natives give a 94 MB PDB of 1M publics in 0.3 s.

Written whole by each link, an edit costs that time and that write: far above the edit
loop's budget. The rest of this doc is the patch.

## Patching it per function (not built)

The end state: an edit's update encodes the functions the link changed and writes their
records and the tables that index them, as the ELF side file does. A body edit of a
dev image moves one function, keeps its name, changes its rows.

### Layout with room

- **MSF.** A stream is a list of blocks. A stream that outgrows its blocks takes blocks at the
  file's end; the directory and the block map are rewritten then, and only then. Blocks a
  stream gives up are marked free in the free block maps and reused by the next growth.
- **The module's symbols.** Each function's `S_GPROC32` and `S_END` are its slot. Free room
  after the last slot is one `S_SKIP` record (0x0007, MSVC's room for incremental links),
  which every reader steps over; `SymByteSize` covers the room. A record of the same size
  (same name) is rewritten in place. A larger one goes at the start of the room, and its old
  slot becomes an `S_SKIP` of its size; its `S_PROCREF` is rewritten to the new offset.
- **The module's line tables.** Each function's `DEBUG_S_LINES` subsection is a slot rounded
  up with a quarter of room (at least 16 bytes); the slack is a `DEBUG_S_IGNORE` subsection
  (kind 0x80000000), which readers skip. Rows that fit their slot are rewritten in place;
  rows that do not move to the room at the end, and the old slot becomes one
  `DEBUG_S_IGNORE`. The files' entries (`DEBUG_S_FILECHKSMS`) keep room for new files the
  same way; the line tables name a file by its entry's offset, which never changes.
- **The symbol record stream.** A function's `S_PUB32` and `S_PROCREF` keep their offsets: the
  same name is the same size, rewritten in place. New ones are appended; a removed function's
  are left unreferenced.
- **The GSI hashes** (publics, globals) are rewritten when the set of names changes, not when
  a function moves.
- **The address map** (publics by address) is rewritten from the moved function's old index to
  its new one: 4 bytes per public in between.
- **DBI** (one module, its contributions, the section map, the files) is small and rewritten
  whole when a contribution or a file changes. **`/names`** is rewritten whole when a file is
  added.

When there is no room (a slot region full, a stream past its blocks with no free run), the
update lays the file out whole with new room, and `DebugWrite::whole` says why.

### Cost of a body edit

The function's procedure (in place), its line table (in place when its rows fit), its
public (in place), and the address map between its old and new place. Encoded: one
function. Written: three blocks and the map's span, against 174 MB whole. The floor is the
three blocks; the address map's span is above it, and is what to cut next (a map ordered so
a dev image's edits move least, or Rust publics left out where cdb's breakpoints by name do
not need them).

### Tests

- **Refinement (Hegel).** For random programs and random sequences of edits (bodies,
  renames, added and removed functions, new files), the PDB patched by each update reads as
  the PDB written whole from the same input: the same procedures with their places and
  sizes, rows, publics and globals, through an independent reader of the format. A planted
  bug (a slot written without its `End` fixed, a moved record whose reference is not) is
  caught.
- **Run.** The run tier's dbghelp program after an edit: the edited function's new name or
  line.
- **Readers.** `llvm-pdbutil dump -all` of a patched PDB reads every stream; cdb names the
  frames.
