//! Unwind tables of Windows (`.pdata` and `.xdata`) and what a landing pad needs there.
//!
//! Windows unwinds in two passes and expects the code that runs on the way to be functions
//! of their own, which the unwinder calls and which return to it. Our landing pads are
//! blocks of the function instead, entered once and never returned from, and Cranelift has
//! no call that names its pad for the calling convention of Windows. So a call with a pad
//! is a plain call followed by a look at a slot of the frame ([`ARRIVAL`]), and the
//! function's handler is the personality of blaze's standard library
//! (`library/std/src/sys/personality/blaze_seh.rs`), which reads the function's [`Pads`]:
//! while a handler is looked for it claims an exception at a pad that catches
//! (`catch_unwind`'s, [`catching`]); while frames are unwound it runs a pad that cleans up,
//! by unwinding to it, and the pad throws the exception again ([`RESUME`]) when it is done.
//!
//! LLVM has calls that name their pad, and its code keeps nothing where Cranelift's has
//! the slot. A call of its code goes on at the pad instead of where it returns to, with
//! the exception in the register a function returns in ([`Pads`]).

use blaze_format::cursor::Put;
use cranelift_codegen::{ir, isa::unwind::winx64};

/// Throws again what a landing pad was entered with. Takes the pad's exception.
pub(in super::super) const RESUME: &str = "blaze.seh.resume";
/// Frees what a landing pad that stops the unwind was entered with.
pub(in super::super) const RELEASE: &str = "blaze.seh.release";
/// The personality LLVM's code names, which only says what its table of pads is like: what
/// the linker names as a function's handler is `unwind::PERSONALITY`.
pub(in super::super) const PERSONALITY: &str = "blaze.seh.personality";

/// The bit of a source location that marks a call that has a landing pad, for [`function`]
/// to find them. The rest is the statement the call is of, as without it. Bit 31 is
/// Cranelift's (`MaybeRelSourceLoc`), which drops it from every location it keeps.
const GUARDED: u32 = 1 << 30;
/// The bit, beside [`GUARDED`], of a call whose pad stops the unwind (`catch_unwind`'s).
const CATCHING: u32 = 1 << 28;

/// The source location of a call of the statement at `loc` that has a landing pad.
pub(in super::super) fn guarded(loc: ir::SourceLoc) -> ir::SourceLoc {
    ir::SourceLoc::new(unguarded(loc).bits() | GUARDED)
}

/// The source location of a call of the statement at `loc` whose landing pad stops the unwind.
pub(in super::super) fn catching(loc: ir::SourceLoc) -> ir::SourceLoc {
    ir::SourceLoc::new(unguarded(loc).bits() | GUARDED | CATCHING)
}

pub(in super::super) fn is_guarded(loc: ir::SourceLoc) -> bool {
    !loc.is_default() && loc.bits() & GUARDED != 0
}

/// Whether a guarded call's pad stops the unwind ([`catching`]).
pub(in super::super) fn is_catching(loc: ir::SourceLoc) -> bool {
    is_guarded(loc) && loc.bits() & CATCHING != 0
}

/// The source location without the marks, which says the statement alone.
pub(in super::super) fn unguarded(loc: ir::SourceLoc) -> ir::SourceLoc {
    if loc.is_default() {
        ir::SourceLoc::new(0)
    } else {
        ir::SourceLoc::new(loc.bits() & !(GUARDED | CATCHING | IN_BOUNDS))
    }
}

/// The mark of an `iadd` that offsets a pointer within what it points into, as the `offset`
/// intrinsic does: LLVM builds it as `getelementptr inbounds`.
const IN_BOUNDS: u32 = 1 << 29;

pub(in super::super) fn in_bounds(loc: ir::SourceLoc) -> ir::SourceLoc {
    let bits = if loc.is_default() { 0 } else { loc.bits() };
    ir::SourceLoc::new(bits | IN_BOUNDS)
}

pub(in super::super) fn is_in_bounds(loc: ir::SourceLoc) -> bool {
    !loc.is_default() && loc.bits() & IN_BOUNDS != 0
}
/// Where a call that unwound finds its exception, from the frame pointer: the first of
/// the four slots a caller leaves above the return address for the function to use as it
/// likes, which Cranelift's code does not use otherwise.
pub(in super::super) const ARRIVAL: i32 = 16;
/// Where the thrown object is in the exception a landing pad is entered with. Before it
/// are what throwing it again takes: its `ThrowInfo`, the image that is relative to, the
/// size of the object, and where it was thrown from (`blaze_seh.rs`'s `OBJECT`).
pub(in super::super) const OBJECT: i64 = 32;

/// A function's `UNWIND_INFO` without a handler, and how long its code is.
#[derive(Debug, PartialEq, Eq, serde_derive::Serialize, serde_derive::Deserialize)]
pub(super) struct Frame {
    pub(super) len: u32,
    pub(super) info: Vec<u8>,
}

/// The calls of a function that have a landing pad, as the personality reads them after
/// their number: three `u32` each, all from the start of the function. A call that returns
/// to an address after the first and no later than the second has a pad, which is at the
/// third; or, where that is zero, the call returns with the exception in [`ARRIVAL`]. The
/// first has [`Pads::CATCHES`] set when the pad stops the unwind.
#[derive(Default)]
pub(in super::super) struct Pads(Vec<u8>);

impl Pads {
    /// The mark in an entry's first word of a pad that stops the unwind
    /// (`blaze_seh.rs`'s `CATCHES`); no function is 2 GiB long.
    pub(in super::super) const CATCHES: u32 = 1 << 31;

    /// A call that returns to `returns_to` and looks at [`ARRIVAL`] when it has.
    pub(super) fn returning(&mut self, returns_to: u32, catches: bool) {
        self.entered(returns_to - 1..returns_to, 0, catches);
    }

    /// Calls that return to an address after `calls.start` and no later than `calls.end`,
    /// and go on at `pad` when they unwind; `catches` when the pad stops the unwind.
    pub(in super::super) fn entered(
        &mut self,
        calls: std::ops::Range<u32>,
        pad: u32,
        catches: bool,
    ) {
        let first = calls.start | if catches { Self::CATCHES } else { 0 };
        for word in [first, calls.end, pad] {
            self.0.put_u32(word);
        }
    }

    pub(in super::super) fn finish(self) -> Option<Vec<u8>> {
        (!self.0.is_empty()).then_some(self.0)
    }
}

/// The frame of compiled code and the calls in it that have a landing pad.
pub(super) fn function(
    code: &cranelift_codegen::CompiledCode,
    info: &winx64::UnwindInfo,
) -> Result<(Frame, Option<Vec<u8>>), String> {
    // alloc: the frame's `UNWIND_INFO` as it is when no register is saved, its input otherwise
    let mut bytes = vec![0; info.emit_size()];
    info.emit(&mut bytes);
    let bytes = with_saves(bytes)?;
    let mut calls = Pads::default();
    let mut ranges = Ranges { ranges: code.buffer.get_srclocs_sorted(), at: 0, last: 0 };
    for call_site in code.buffer.call_sites() {
        // The call ends where it returns to, which may be where the next thing starts.
        if let Some(it) = ranges.of(call_site.ret_addr - 1)
            && is_guarded(it.loc.as_abs())
        {
            calls.returning(call_site.ret_addr, is_catching(it.loc.as_abs()));
        }
    }
    let frame = Frame { len: code.buffer.data().len() as u32, info: bytes };
    Ok((frame, calls.finish()))
}

/// Finds the source location of each of offsets that mostly come in order, in ranges that are
/// in order and do not overlap: from where the one before was found, so the calls of a
/// function are matched to their statements in one walk over both.
struct Ranges<'a> {
    ranges: &'a [SrcLoc],
    at: usize,
    last: u32,
}

type SrcLoc = cranelift_codegen::MachSrcLoc;

impl<'a> Ranges<'a> {
    fn of(&mut self, offset: u32) -> Option<&'a SrcLoc> {
        if offset < self.last {
            self.at = 0;
        }
        self.last = offset;
        while self.ranges.get(self.at).is_some_and(|it| it.end <= offset) {
            self.at += 1;
        }
        self.ranges.get(self.at).filter(|it| it.start <= offset)
    }
}

const UWOP_PUSH_NONVOL: u8 = 0;
const UWOP_ALLOC_LARGE: u8 = 1;
const UWOP_ALLOC_SMALL: u8 = 2;
const UWOP_SET_FPREG: u8 = 3;
const UWOP_SAVE_NONVOL: u8 = 4;
const UWOP_SAVE_XMM128: u8 = 8;

/// Cranelift's `UNWIND_INFO` with where the registers the function saves are.
///
/// Cranelift's code saves them below the frame pointer, in the order it names them: those
/// of eight bytes and then those of sixteen. Its `UNWIND_INFO` means to say so by having
/// the frame start that far below the frame pointer, but what it writes loses the
/// distance (it shifts it out of the byte) and halves where each register of eight bytes
/// is. That finds the frames, which is what Wasmtime needs of it, and gives the registers
/// values they never had, which is not enough to run a frame again. So this writes the
/// distance, the places, and an allocation of the distance that the code does not have
/// by itself, for the unwinder to find the frame pointer's own slot from where the frame
/// starts.
fn with_saves(info: Vec<u8>) -> Result<Vec<u8>, String> {
    // alloc: the error's message
    let unknown = |op: u8| format!("an unwind code {op} of Cranelift's");
    let nodes = &info[4..4 + usize::from(info[2]) * 2];
    // (offset in the prologue, operation, register, how many words follow)
    let mut codes = Vec::with_capacity(nodes.len() / 2);
    let mut at = 0;
    while at < nodes.len() {
        let (offset, op, register) = (nodes[at], nodes[at + 1] & 0xf, nodes[at + 1] >> 4);
        let following = match op {
            UWOP_PUSH_NONVOL | UWOP_SET_FPREG => 0,
            UWOP_SAVE_NONVOL | UWOP_SAVE_XMM128 => 1,
            _ => return Err(unknown(op)),
        };
        let word = u16::from_le_bytes([nodes[at + 2 * following], nodes[at + 2 * following + 1]]);
        codes.push((offset, op, register, word));
        at += 2 + 2 * following;
    }
    // The codes are last first.
    let words = codes.iter().filter(|code| code.1 == UWOP_SAVE_NONVOL).count();
    let vectors = codes.iter().filter(|code| code.1 == UWOP_SAVE_XMM128).map(|code| code.3 + 1);
    let saved = vectors.max().map_or(words.next_multiple_of(2) * 8, |end| usize::from(end) * 16);
    if saved == 0 {
        return Ok(info);
    }
    if saved > 240 {
        // alloc: the error's message
        return Err(format!("{saved} bytes of saved registers"));
    }
    // The header, then at most six bytes of each code and two of padding.
    let mut out = Vec::with_capacity(4 + 6 * codes.len() + 2);
    out.extend([info[0], info[1], 0, 0]);
    let mut word = words;
    for (offset, op, register, following) in codes {
        out.extend([offset, register << 4 | op]);
        match op {
            UWOP_SAVE_NONVOL => {
                word -= 1;
                out.extend((word as u16).to_le_bytes());
            }
            UWOP_SAVE_XMM128 => out.extend(following.to_le_bytes()),
            UWOP_SET_FPREG if saved <= 128 => {
                out.extend([offset, (((saved - 8) / 8) as u8 * 16) | UWOP_ALLOC_SMALL]);
            }
            UWOP_SET_FPREG => {
                out.extend([offset, UWOP_ALLOC_LARGE]);
                out.extend((saved as u16 / 8).to_le_bytes());
            }
            _ => (),
        }
    }
    let count = (out.len() - 4) / 2;
    out.resize(out.len().next_multiple_of(4), 0);
    out[2] = count as u8;
    out[3] = ((saved / 16) as u8 * 16) | (info[3] & 0xf);
    Ok(out)
}

#[test]
fn ranges_find_what_a_search_of_all_of_them_finds() {
    let mut rng = blaze_ids::rng::SplitMix64::new(0x9e37_79b9_7f4a_7c15);
    let mut next = move |below: u32| rng.below(u64::from(below)) as u32;
    for _ in 0..200 {
        // alloc: a test's input
        let mut ranges = Vec::new();
        let mut at = 0;
        for line in 0..next(40) {
            let start = at + next(4);
            let end = start + next(12);
            let loc = ir::MaybeRelSourceLoc::abs(ir::SourceLoc::new(line));
            ranges.push(SrcLoc { start, end, loc });
            at = end;
        }
        let mut found = Ranges { ranges: &ranges, at: 0, last: 0 };
        let mut offset = 0;
        for _ in 0..60 {
            // Mostly onwards, as calls come, and now and then back.
            offset = match next(8) {
                0 => next(at + 1),
                _ => offset + next(6),
            };
            let all = ranges.iter().find(|it| (it.start..it.end).contains(&offset));
            assert_eq!(found.of(offset), all, "{offset} in {ranges:?}");
        }
    }
}
