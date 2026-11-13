---
status: current
summary: A PE image's PDB is its side file - MSF 7.0 with the PDB info stream (the image's build id as GUID, age 1), empty TPI and IPI, DBI with one module of every Rust function, its section contributions, section map, files and the image's section headers, the module's `S_GPROC32` procedures and C13 line tables, globals for Rust functions and publics for native ones - giving std's backtrace (dbghelp) names and lines and cdb breakpoints by name. Built - laid out whole (400,000 functions in 0.30 s) and patched per function by each link's change (an edit of a desktop-sized PDB writes about 340 bytes in about 1 ms), a Hegel refinement test and a run-tier test through dbghelp. Not built - types, locals, inline sites, the C objects' own `.debug$S`.
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
procedure), publics (an `S_PUB32` per native function, the GSI hash, the address map; a Rust
function needs none: dbghelp and cdb find it by its procedure), the symbol record stream, the image's section headers, and one module, `blaze`:
`S_OBJNAME`, `S_COMPILE3` (Rust, x64), an `S_GPROC32` and `S_END` per function, then the C13
subsections, its files and a line table per function. The rows are the ones the ELF and
Mach-O side files' `.debug_line` is made of (`Image::debug_file`'s views), so one source feeds
every format. Native functions are publics named as their objects name them
(`native::Resolved::native_functions`); their own `.debug$S` is dropped.

Out of scope: types and locals, inline sites (from `CompiledFunction.inlined`, later), a module
per crate.

## Cost, written whole

Measured (`pe::pdb::tests::a_desktop_sized_pdb`, release, adais): 400,000 functions of 10 rows
in 2,000 files, with names as long as rustc's v0 names, take 0.30 s and make 142 MB with
room (174 MB before Rust publics were left out). Per function that is about 350 bytes: the
name twice (procedure, reference), the procedure, the line table with room, the hash. The desktop's rustc objects linked
as natives give a 94 MB PDB of 1M publics in 0.3 s.

Written whole by each link, an edit costs that time and that write: far above the edit
loop's budget. The rest of this doc is the patch.

## Patching it per function

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
- **The symbol record stream.** A function's `S_PROCREF` keeps its offset: rewritten in place
  when its procedure moves. A new or renamed function's is appended; a removed function's is
  left unreferenced.
- **The globals' hash** is rewritten when the set of names changes, not when a function
  moves. **The publics** are the native code's alone: a change of them (`Resolved`'s
  `natives_version`) lays the file out whole.
- **DBI** (one module, its contributions, the section map, the files) is small and rewritten
  whole when a contribution or a file changes. **`/names`** is rewritten whole when a file is
  added.

When there is no room (a slot region full, a stream past its blocks with no free run), the
update lays the file out whole with new room, and `DebugWrite::whole` says why.

### Cost of a body edit

The function's procedure (in place), its line table (in place when its rows fit), DBI's
contribution, the build id. Measured (`a_desktop_sized_patch`, 400,000 functions): about
340 bytes in 3 or 4 writes, in 0.7-1.4 ms, against 142 MB whole. DBI's contributions are runs
of a sorted list of the procedures' places, kept by each patch; what is left of the time is
DBI's runs made again (O(functions), a linear pass) and the directory compared.

### Tests

- **Refinement (Hegel, built).** `a_pdb_kept_by_patches_reads_as_one_laid_out_whole`: for
  random sequences of edits (bodies, renames, added and removed functions, new files), the PDB
  patched by each update reads as the PDB laid out whole from the same program, through an
  independent reader of the format (procedures, places, rows, references, build id). Its
  control: a patch applied without one of its writes is caught.
- **Run (built).** `dbghelp_names_a_rust_function_and_its_line_from_the_pdb` edits the
  function and reads the patched PDB's new line through dbghelp.
- **Readers.** `llvm-pdbutil dump` reads every stream of a whole PDB; cdb names the frames.
