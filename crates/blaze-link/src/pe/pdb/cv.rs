//! CodeView record constants, primitive types, numeric leaves, TPI/IPI hashing,
//! DWARF-to-CodeView x86-64 location translation, and `S_INLINESITE` binary annotations.
//!
//! Every constant and binary layout follows Microsoft's `cvinfo.h` and LLVM's
//! `DebugInfo/CodeView` definitions.

use super::hash_v1;

// CodeView TypeLeafKind (CodeViewTypes.def).
pub(crate) const LF_MODIFIER: u16 = 0x1001;
pub(crate) const LF_POINTER: u16 = 0x1002;
pub(crate) const LF_PROCEDURE: u16 = 0x1008;
pub(crate) const LF_MFUNCTION: u16 = 0x1009;
pub(crate) const LF_VTSHAPE: u16 = 0x000a;
pub(crate) const LF_LABEL: u16 = 0x000e;
pub(crate) const LF_ENDPRECOMP: u16 = 0x0014;
pub(crate) const LF_ARGLIST: u16 = 0x1201;
pub(crate) const LF_FIELDLIST: u16 = 0x1203;
pub(crate) const LF_BITFIELD: u16 = 0x1205;
pub(crate) const LF_METHODLIST: u16 = 0x1206;
pub(crate) const LF_BCLASS: u16 = 0x1400;
pub(crate) const LF_VBCLASS: u16 = 0x1401;
pub(crate) const LF_IVBCLASS: u16 = 0x1402;
pub(crate) const LF_INDEX: u16 = 0x1404;
pub(crate) const LF_VFUNCTAB: u16 = 0x1409;
pub(crate) const LF_VFUNCOFF: u16 = 0x140c;
pub(crate) const LF_ENUMERATE: u16 = 0x1502;
pub(crate) const LF_ARRAY: u16 = 0x1503;
pub(crate) const LF_CLASS: u16 = 0x1504;
pub(crate) const LF_STRUCTURE: u16 = 0x1505;
pub(crate) const LF_UNION: u16 = 0x1506;
pub(crate) const LF_ENUM: u16 = 0x1507;
pub(crate) const LF_PRECOMP: u16 = 0x1509;
pub(crate) const LF_MEMBER: u16 = 0x150d;
pub(crate) const LF_STMEMBER: u16 = 0x150e;
pub(crate) const LF_METHOD: u16 = 0x150f;
pub(crate) const LF_NESTTYPE: u16 = 0x1510;
pub(crate) const LF_ONEMETHOD: u16 = 0x1511;
pub(crate) const LF_NESTTYPEEX: u16 = 0x1512;
pub(crate) const LF_TYPESERVER2: u16 = 0x1515;
pub(crate) const LF_INTERFACE: u16 = 0x1519;
pub(crate) const LF_BINTERFACE: u16 = 0x151a;
pub(crate) const LF_VFTABLE: u16 = 0x151d;

// IPI ItemId leaves (0x1601..=0x1607).
pub(crate) const LF_FUNC_ID: u16 = 0x1601;
pub(crate) const LF_MFUNC_ID: u16 = 0x1602;
pub(crate) const LF_BUILDINFO: u16 = 0x1603;
pub(crate) const LF_SUBSTR_LIST: u16 = 0x1604;
pub(crate) const LF_STRING_ID: u16 = 0x1605;
pub(crate) const LF_UDT_SRC_LINE: u16 = 0x1606;
pub(crate) const LF_UDT_MOD_SRC_LINE: u16 = 0x1607;

// Numeric leaf tags.
pub(crate) const LF_CHAR: u16 = 0x8000;
pub(crate) const LF_SHORT: u16 = 0x8001;
pub(crate) const LF_USHORT: u16 = 0x8002;
pub(crate) const LF_LONG: u16 = 0x8003;
pub(crate) const LF_ULONG: u16 = 0x8004;
pub(crate) const LF_QUADWORD: u16 = 0x8009;
pub(crate) const LF_UQUADWORD: u16 = 0x800a;

// CodeView SymbolKind (CodeViewSymbols.def).
pub(crate) const S_END: u16 = 0x0006;
pub(crate) const S_SKIP: u16 = 0x0007;
pub(crate) const S_FRAMEPROC: u16 = 0x1012;
pub(crate) const S_OBJNAME: u16 = 0x1101;
pub(crate) const S_THUNK32: u16 = 0x1102;
pub(crate) const S_BLOCK32: u16 = 0x1103;
pub(crate) const S_LABEL32: u16 = 0x1105;
pub(crate) const S_REGISTER: u16 = 0x1106;
pub(crate) const S_CONSTANT: u16 = 0x1107;
pub(crate) const S_UDT: u16 = 0x1108;
pub(crate) const S_BPREL32: u16 = 0x110b;
pub(crate) const S_LDATA32: u16 = 0x110c;
pub(crate) const S_GDATA32: u16 = 0x110d;
pub(crate) const S_PUB32: u16 = 0x110e;
pub(crate) const S_LPROC32: u16 = 0x110f;
pub(crate) const S_GPROC32: u16 = 0x1110;
pub(crate) const S_REGREL32: u16 = 0x1111;
pub(crate) const S_LTHREAD32: u16 = 0x1112;
pub(crate) const S_GTHREAD32: u16 = 0x1113;
pub(crate) const S_COMPILE2: u16 = 0x1116;
pub(crate) const S_PROCREF: u16 = 0x1125;
pub(crate) const S_LPROCREF: u16 = 0x1127;
pub(crate) const S_TRAMPOLINE: u16 = 0x112c;
pub(crate) const S_CALLSITEINFO: u16 = 0x1139;
pub(crate) const S_FRAMECOOKIE: u16 = 0x113a;
pub(crate) const S_COMPILE3: u16 = 0x113c;
pub(crate) const S_ENVBLOCK: u16 = 0x113d;
pub(crate) const S_LOCAL: u16 = 0x113e;
pub(crate) const S_DEFRANGE: u16 = 0x113f;
pub(crate) const S_DEFRANGE_SUBFIELD: u16 = 0x1140;
pub(crate) const S_DEFRANGE_REGISTER: u16 = 0x1141;
pub(crate) const S_DEFRANGE_FRAMEPOINTER_REL: u16 = 0x1142;
pub(crate) const S_DEFRANGE_SUBFIELD_REGISTER: u16 = 0x1143;
pub(crate) const S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE: u16 = 0x1144;
pub(crate) const S_DEFRANGE_REGISTER_REL: u16 = 0x1145;
pub(crate) const S_LPROC32_ID: u16 = 0x1146;
pub(crate) const S_GPROC32_ID: u16 = 0x1147;
pub(crate) const S_BUILDINFO: u16 = 0x114c;
pub(crate) const S_INLINESITE: u16 = 0x114d;
pub(crate) const S_INLINESITE_END: u16 = 0x114e;
pub(crate) const S_PROC_ID_END: u16 = 0x114f;
pub(crate) const S_FILESTATIC: u16 = 0x1153;
pub(crate) const S_CALLEES: u16 = 0x115a;
pub(crate) const S_CALLERS: u16 = 0x115b;
pub(crate) const S_INLINESITE2: u16 = 0x115d;
pub(crate) const S_HEAPALLOCSITE: u16 = 0x115e;
pub(crate) const S_INLINEES: u16 = 0x1168;
pub(crate) const S_DEFRANGE_REGISTER_REL_INDIR: u16 = 0x1177;

// C13 DebugSubsectionKind.
pub(crate) const DEBUG_S_SYMBOLS: u32 = 0xf1;
pub(crate) const DEBUG_S_LINES: u32 = 0xf2;
pub(crate) const DEBUG_S_STRINGTABLE: u32 = 0xf3;
pub(crate) const DEBUG_S_FILECHKSMS: u32 = 0xf4;
pub(crate) const DEBUG_S_INLINEELINES: u32 = 0xf6;
pub(crate) const DEBUG_S_IGNORE: u32 = 0x8000_0000;

// Simple TypeIndex values (< 0x1000).
pub(crate) const FIRST_NON_SIMPLE: u32 = 0x1000;
pub(crate) const T_NOTYPE: u32 = 0x0000;
pub(crate) const T_VOID: u32 = 0x0003;
pub(crate) const T_SCHAR: u32 = 0x0010;
pub(crate) const T_SHORT: u32 = 0x0011;
pub(crate) const T_UCHAR: u32 = 0x0020;
pub(crate) const T_USHORT: u32 = 0x0021;
pub(crate) const T_BOOL08: u32 = 0x0030;
pub(crate) const T_REAL32: u32 = 0x0040;
pub(crate) const T_REAL64: u32 = 0x0041;
pub(crate) const T_REAL128: u32 = 0x0043;
pub(crate) const T_REAL16: u32 = 0x0046;
pub(crate) const T_INT4: u32 = 0x0074;
pub(crate) const T_UINT4: u32 = 0x0075;
pub(crate) const T_INT8: u32 = 0x0076;
pub(crate) const T_UINT8: u32 = 0x0077;
pub(crate) const T_INT16: u32 = 0x0078;
pub(crate) const T_UINT16: u32 = 0x0079;
pub(crate) const T_CHAR32: u32 = 0x007b;

// ClassOptions bits.
pub(crate) const OPT_NESTED: u16 = 0x0008;
pub(crate) const OPT_CONTAINS_NESTED: u16 = 0x0010;
pub(crate) const OPT_FORWARD_REF: u16 = 0x0080;
pub(crate) const OPT_HAS_UNIQUE_NAME: u16 = 0x0200;

// Member access: public.
pub(crate) const ACCESS_PUBLIC: u16 = 0x0003;

// Pointer attributes: Near64 (0x0c) | Pointer mode (0 << 5) | Size 8 (8 << 13).
pub(crate) const PTR64_ATTRS: u32 = 0x0c | (8 << 13);

// LocalSymFlags bits.
pub(crate) const LOCAL_IS_PARAM: u16 = 1 << 0;
pub(crate) const LOCAL_IS_OPTIMIZED_OUT: u16 = 1 << 8;

// DefRangeRegisterRel flags.
pub(crate) const DEFRANGE_IS_SUBFIELD: u16 = 1 << 0;
pub(crate) const DEFRANGE_OFFSET_SHIFT: u16 = 4;
pub(crate) const MAX_DEFRANGE: u32 = 0xf000;

// CodeView x86-64 register IDs (CodeViewRegisters.def).
pub(crate) const CV_AMD64_RAX: u16 = 328;
pub(crate) const CV_AMD64_RBX: u16 = 329;
pub(crate) const CV_AMD64_RCX: u16 = 330;
pub(crate) const CV_AMD64_RDX: u16 = 331;
pub(crate) const CV_AMD64_RSI: u16 = 332;
pub(crate) const CV_AMD64_RDI: u16 = 333;
pub(crate) const CV_AMD64_RBP: u16 = 334;
pub(crate) const CV_AMD64_RSP: u16 = 335;
pub(crate) const CV_AMD64_R8: u16 = 336;
pub(crate) const CV_AMD64_R13: u16 = 341;
pub(crate) const CV_AMD64_XMM0: u16 = 154;
pub(crate) const CV_AMD64_XMM8: u16 = 252;

// S_INLINESITE BinaryAnnotationsOpCode.
pub(crate) const BA_EOF: u32 = 0;
pub(crate) const BA_CODE_OFFSET: u32 = 1;
pub(crate) const BA_CHANGE_CODE_OFFSET_BASE: u32 = 2;
pub(crate) const BA_CHANGE_CODE_OFFSET: u32 = 3;
pub(crate) const BA_CHANGE_CODE_LENGTH: u32 = 4;
pub(crate) const BA_CHANGE_FILE: u32 = 5;
pub(crate) const BA_CHANGE_LINE_OFFSET: u32 = 6;
pub(crate) const BA_CHANGE_LINE_END_DELTA: u32 = 7;
pub(crate) const BA_CHANGE_RANGE_KIND: u32 = 8;
pub(crate) const BA_CHANGE_COLUMN_START: u32 = 9;
pub(crate) const BA_CHANGE_COLUMN_END_DELTA: u32 = 10;
pub(crate) const BA_CHANGE_CODE_OFFSET_AND_LINE_OFFSET: u32 = 11;
pub(crate) const BA_CHANGE_CODE_LENGTH_AND_CODE_OFFSET: u32 = 12;
pub(crate) const BA_CHANGE_COLUMN_END: u32 = 13;

/// Number of hash buckets in TPI and IPI streams (`MaxTpiHashBuckets - 1`, matching
/// `pe/pdb.rs` and LLVM's `TpiStreamBuilder`).
pub(crate) const TPI_HASH_BUCKETS: u32 = 0x3ffff;

/// Whether a CodeView type leaf kind belongs to the IPI (Item ID) stream rather than TPI.
pub(crate) const fn is_ipi_kind(kind: u16) -> bool {
    matches!(
        kind,
        LF_FUNC_ID
            | LF_MFUNC_ID
            | LF_BUILDINFO
            | LF_SUBSTR_LIST
            | LF_STRING_ID
            | LF_UDT_SRC_LINE
            | LF_UDT_MOD_SRC_LINE
    )
}

/// Pads `buf` to a 4-byte boundary using CodeView `LF_PAD3`/`LF_PAD2`/`LF_PAD1` bytes.
pub(crate) fn pad_type(buf: &mut Vec<u8>) {
    let rem = (4 - (buf.len() % 4)) % 4;
    for n in (1..=rem).rev() {
        buf.push(0xf0 + n as u8);
    }
}

/// Encodes an unsigned CodeView numeric leaf into `out`.
pub(crate) fn write_numeric_u64(out: &mut Vec<u8>, value: u64) {
    if value < 0x8000 {
        out.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= u64::from(u16::MAX) {
        out.extend_from_slice(&LF_USHORT.to_le_bytes());
        out.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value <= u64::from(u32::MAX) {
        out.extend_from_slice(&LF_ULONG.to_le_bytes());
        out.extend_from_slice(&(value as u32).to_le_bytes());
    } else {
        out.extend_from_slice(&LF_UQUADWORD.to_le_bytes());
        out.extend_from_slice(&value.to_le_bytes());
    }
}

/// Decodes a CodeView numeric leaf starting at `bytes`, returning `(value, bytes_consumed)`.
pub(crate) fn read_numeric(bytes: &[u8]) -> Option<(u64, usize)> {
    if bytes.len() < 2 {
        return None;
    }
    let tag = u16::from_le_bytes([bytes[0], bytes[1]]);
    if tag < 0x8000 {
        return Some((u64::from(tag), 2));
    }
    match tag {
        LF_CHAR => bytes.get(2).map(|b| (*b as i8 as i64 as u64, 3)),
        LF_SHORT => (bytes.len() >= 4)
            .then(|| (i16::from_le_bytes([bytes[2], bytes[3]]) as i64 as u64, 4)),
        LF_USHORT => {
            (bytes.len() >= 4).then(|| (u64::from(u16::from_le_bytes([bytes[2], bytes[3]])), 4))
        }
        LF_LONG => (bytes.len() >= 6)
            .then(|| (i32::from_le_bytes(bytes[2..6].try_into().unwrap()) as i64 as u64, 6)),
        LF_ULONG => (bytes.len() >= 6)
            .then(|| (u64::from(u32::from_le_bytes(bytes[2..6].try_into().unwrap())), 6)),
        LF_QUADWORD => (bytes.len() >= 10)
            .then(|| (i64::from_le_bytes(bytes[2..10].try_into().unwrap()) as u64, 10)),
        LF_UQUADWORD => {
            (bytes.len() >= 10).then(|| (u64::from_le_bytes(bytes[2..10].try_into().unwrap()), 10))
        }
        _ => None,
    }
}

/// Skips a NUL-terminated string starting at `at`, returning `(str_bytes, next_offset)`.
pub(crate) fn read_cstr(bytes: &[u8], at: usize) -> Option<(&[u8], usize)> {
    let tail = bytes.get(at..)?;
    let nul = tail.iter().position(|&b| b == 0)?;
    Some((&tail[..nul], at + nul + 1))
}

/// IEEE jamcrc (`!crc32(bytes)`), matching Microsoft's and LLVM's `hashBufferV8`.
pub(crate) fn hash_buffer_v8(bytes: &[u8]) -> u32 {
    !crate::beside::crc32(bytes)
}

/// Computes the TPI/IPI hash value (before `% num_buckets`) for a complete CodeView type
/// record (`[len: u16, kind: u16, body...]`), following LLVM's `TpiHashing.cpp`:
/// named non-forward-reference UDTs hash their name (or unique name) via `hash_v1`;
/// `LF_UDT_SRC_LINE` / `LF_UDT_MOD_SRC_LINE` hash their UDT `TypeIndex`; all other records
/// hash the full record via `hash_buffer_v8`.
pub(crate) fn hash_type_record(record: &[u8]) -> u32 {
    if record.len() < 4 {
        return hash_buffer_v8(record);
    }
    let kind = u16::from_le_bytes([record[2], record[3]]);
    let body = &record[4..];
    match kind {
        LF_CLASS | LF_STRUCTURE | LF_INTERFACE | LF_UNION | LF_ENUM => {
            if body.len() < 12 {
                return hash_buffer_v8(record);
            }
            let props = u16::from_le_bytes([body[2], body[3]]);
            if props & OPT_FORWARD_REF != 0 {
                return hash_buffer_v8(record);
            }
            let name_at = match kind {
                LF_CLASS | LF_STRUCTURE | LF_INTERFACE => {
                    let Some((_, n)) = body.get(16..).and_then(read_numeric) else {
                        return hash_buffer_v8(record);
                    };
                    16 + n
                }
                LF_UNION => {
                    let Some((_, n)) = body.get(8..).and_then(read_numeric) else {
                        return hash_buffer_v8(record);
                    };
                    8 + n
                }
                LF_ENUM => 12,
                _ => unreachable!(),
            };
            let Some((name, after_name)) = read_cstr(body, name_at) else {
                return hash_buffer_v8(record);
            };
            if name.is_empty() || name == b"<unnamed-tag>" || name == b"__unnamed" {
                return hash_buffer_v8(record);
            }
            if props & OPT_HAS_UNIQUE_NAME != 0
                && let Some((unique, _)) = read_cstr(body, after_name)
                && !unique.is_empty()
            {
                return hash_v1(unique);
            }
            hash_v1(name)
        }
        LF_UDT_SRC_LINE | LF_UDT_MOD_SRC_LINE if body.len() >= 4 => hash_buffer_v8(&body[..4]),
        _ => hash_buffer_v8(record),
    }
}

/// Maps a primitive [`blaze_codegen::debug::BaseEncoding`] and byte size to a CodeView simple
/// `TypeIndex`.
pub(crate) fn primitive_type(
    encoding: blaze_codegen::debug::BaseEncoding,
    size: u64,
) -> u32 {
    use blaze_codegen::debug::BaseEncoding;
    match (encoding, size) {
        (BaseEncoding::Bool, 1) => T_BOOL08,
        (BaseEncoding::Char, 4) => T_CHAR32,
        (BaseEncoding::Signed, 1) => T_SCHAR,
        (BaseEncoding::Signed, 2) => T_SHORT,
        (BaseEncoding::Signed, 4) => T_INT4,
        (BaseEncoding::Signed, 8) => T_INT8,
        (BaseEncoding::Signed, 16) => T_INT16,
        (BaseEncoding::Unsigned, 1) => T_UCHAR,
        (BaseEncoding::Unsigned, 2) => T_USHORT,
        (BaseEncoding::Unsigned, 4) => T_UINT4,
        (BaseEncoding::Unsigned, 8) => T_UINT8,
        (BaseEncoding::Unsigned, 16) => T_UINT16,
        (BaseEncoding::Float, 2) => T_REAL16,
        (BaseEncoding::Float, 4) => T_REAL32,
        (BaseEncoding::Float, 8) => T_REAL64,
        (BaseEncoding::Float, 16) => T_REAL128,
        _ => T_VOID,
    }
}

/// Underlying unsigned integer simple `TypeIndex` for an enum of `size` bytes.
pub(crate) fn enum_underlying_type(size: u64) -> u32 {
    match size {
        1 => T_UCHAR,
        2 => T_USHORT,
        4 => T_UINT4,
        8 => T_UINT8,
        _ => T_UINT4,
    }
}

/// Maps a DWARF x86-64 register number (System V / gimli `X86_64`) to a CodeView `CV_AMD64_*`
/// register ID.
pub(crate) fn dwarf_x64_reg_to_cv(reg: u16) -> Option<u16> {
    Some(match reg {
        0 => CV_AMD64_RAX,
        1 => CV_AMD64_RDX,
        2 => CV_AMD64_RCX,
        3 => CV_AMD64_RBX,
        4 => CV_AMD64_RSI,
        5 => CV_AMD64_RDI,
        6 => CV_AMD64_RBP,
        7 => CV_AMD64_RSP,
        8..=15 => CV_AMD64_R8 + (reg - 8),
        17..=24 => CV_AMD64_XMM0 + (reg - 17),
        25..=32 => CV_AMD64_XMM8 + (reg - 25),
        _ => return None,
    })
}

/// Encoded frame base register extracted from a DWARF `frame_base` expression.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct FrameBase {
    /// CodeView register ID (for example [`CV_AMD64_RBP`]).
    pub cv_reg: u16,
    /// `EncodedFramePtrReg` (1 = RSP, 2 = RBP, 3 = R13) for `S_FRAMEPROC::Flags`.
    pub encoded: u32,
}

/// Decodes a DWARF `frame_base` expression (such as `[DW_OP_reg6]` = RBP).
pub(crate) fn decode_frame_base(expr: &[u8]) -> Option<FrameBase> {
    let reg = match expr {
        [op] if (0x50..=0x6f).contains(op) => u16::from(op - 0x50),
        [0x90, rest @ ..] => {
            let (r, n) = read_uleb(rest)?;
            if n != rest.len() {
                return None;
            }
            u16::try_from(r).ok()?
        }
        _ => return None,
    };
    let cv_reg = dwarf_x64_reg_to_cv(reg)?;
    let encoded = match cv_reg {
        CV_AMD64_RSP => 1,
        CV_AMD64_RBP => 2,
        CV_AMD64_R13 => 3,
        _ => 0,
    };
    Some(FrameBase { cv_reg, encoded })
}

/// One CodeView variable location translated from a DWARF expression (or piece of one).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum CvLocation {
    /// Variable (or subfield at `subfield_offset`) is in register `reg`.
    Register { reg: u16, subfield_offset: Option<u32> },
    /// Variable is at `frame_pointer + offset` (`S_DEFRANGE_FRAMEPOINTER_REL`).
    FrameRel { offset: i32 },
    /// Variable (or subfield at `subfield_offset`) is in memory at `reg + offset`
    /// (`S_DEFRANGE_REGISTER_REL`).
    RegRel { reg: u16, offset: i32, subfield_offset: Option<u16> },
    /// Variable is in memory at `*(reg + base_offset) + udt_offset`
    /// (`S_DEFRANGE_REGISTER_REL_INDIR`).
    RegRelIndir { reg: u16, base_offset: i32, udt_offset: i32 },
}

/// Translates a DWARF location expression into one or more CodeView locations (splitting on
/// `DW_OP_piece` for multi-piece values). Unsupported expressions yield an empty vec rather
/// than failing the link.
pub(crate) fn translate_dwarf_expr(
    expr: &[u8],
    frame_base: Option<FrameBase>,
) -> Vec<CvLocation> {
    // DWARF opcodes used by Cranelift, Stencil and LLVM.
    const DW_OP_DEREF: u8 = 0x06;
    const DW_OP_PLUS_UCONST: u8 = 0x23;
    const DW_OP_REG0: u8 = 0x50;
    const DW_OP_REG31: u8 = 0x6f;
    const DW_OP_BREG0: u8 = 0x70;
    const DW_OP_BREG31: u8 = 0x8f;
    const DW_OP_REGX: u8 = 0x90;
    const DW_OP_FBREG: u8 = 0x91;
    const DW_OP_BREGX: u8 = 0x92;
    const DW_OP_PIECE: u8 = 0x93;

    let mut out = Vec::new();
    let mut at = 0usize;
    let mut byte_offset = 0u32;
    let has_piece = expr.contains(&DW_OP_PIECE);

    while at < expr.len() {
        // Parse one piece (up to DW_OP_PIECE or end).
        let op = expr[at];
        at += 1;
        enum Base {
            Reg(u16),
            Frame(i64),
            Breg(u16, i64),
        }
        let base = match op {
            DW_OP_REG0..=DW_OP_REG31 => {
                let Some(cv) = dwarf_x64_reg_to_cv(u16::from(op - DW_OP_REG0)) else {
                    return out;
                };
                Base::Reg(cv)
            }
            DW_OP_REGX => {
                let Some((r, n)) = read_uleb(&expr[at..]) else { return out };
                at += n;
                let Some(cv) = u16::try_from(r).ok().and_then(dwarf_x64_reg_to_cv) else {
                    return out;
                };
                Base::Reg(cv)
            }
            DW_OP_FBREG => {
                let Some((off, n)) = read_sleb(&expr[at..]) else { return out };
                at += n;
                Base::Frame(off)
            }
            DW_OP_BREG0..=DW_OP_BREG31 => {
                let Some((off, n)) = read_sleb(&expr[at..]) else { return out };
                at += n;
                let Some(cv) = dwarf_x64_reg_to_cv(u16::from(op - DW_OP_BREG0)) else {
                    return out;
                };
                Base::Breg(cv, off)
            }
            DW_OP_BREGX => {
                let Some((r, n1)) = read_uleb(&expr[at..]) else { return out };
                at += n1;
                let Some((off, n2)) = read_sleb(&expr[at..]) else { return out };
                at += n2;
                let Some(cv) = u16::try_from(r).ok().and_then(dwarf_x64_reg_to_cv) else {
                    return out;
                };
                Base::Breg(cv, off)
            }
            DW_OP_PIECE => {
                // Empty piece (optimized-out bytes): advance offset and continue.
                let Some((size, n)) = read_uleb(&expr[at..]) else { return out };
                at += n;
                byte_offset = byte_offset.saturating_add(size as u32);
                continue;
            }
            _ => return out,
        };

        let mut deref = false;
        let mut post_offset: i64 = 0;
        let mut piece_size: Option<u32> = None;

        while at < expr.len() {
            match expr[at] {
                DW_OP_DEREF if !deref => {
                    at += 1;
                    deref = true;
                }
                DW_OP_PLUS_UCONST => {
                    at += 1;
                    let Some((add, n)) = read_uleb(&expr[at..]) else { return out };
                    at += n;
                    post_offset = post_offset.saturating_add(add as i64);
                }
                DW_OP_PIECE => {
                    at += 1;
                    let Some((size, n)) = read_uleb(&expr[at..]) else { return out };
                    at += n;
                    piece_size = Some(size as u32);
                    break;
                }
                _ => return out,
            }
        }

        let subfield = has_piece.then_some(byte_offset);
        match (base, deref) {
            (Base::Reg(reg), false) if post_offset == 0 => {
                out.push(CvLocation::Register { reg, subfield_offset: subfield });
            }
            (Base::Frame(off), false) => {
                let total = off.saturating_add(post_offset);
                if let Ok(offset) = i32::try_from(total) {
                    if let Some(sub) = subfield {
                        if let Some(fb) = frame_base
                            && let Ok(sub16) = u16::try_from(sub)
                            && sub16 < (1 << 12)
                        {
                            out.push(CvLocation::RegRel {
                                reg: fb.cv_reg,
                                offset,
                                subfield_offset: Some(sub16),
                            });
                        }
                    } else if frame_base.is_some_and(|fb| fb.encoded != 0) {
                        out.push(CvLocation::FrameRel { offset });
                    } else if let Some(fb) = frame_base {
                        out.push(CvLocation::RegRel {
                            reg: fb.cv_reg,
                            offset,
                            subfield_offset: None,
                        });
                    }
                }
            }
            (Base::Frame(off), true) if !has_piece => {
                if let (Some(fb), Ok(base_offset), Ok(udt_offset)) =
                    (frame_base, i32::try_from(off), i32::try_from(post_offset))
                {
                    out.push(CvLocation::RegRelIndir { reg: fb.cv_reg, base_offset, udt_offset });
                }
            }
            (Base::Breg(reg, off), false) => {
                let total = off.saturating_add(post_offset);
                if let Ok(offset) = i32::try_from(total) {
                    let sub16 = subfield.and_then(|s| u16::try_from(s).ok().filter(|&v| v < (1 << 12)));
                    if subfield.is_none() || sub16.is_some() {
                        out.push(CvLocation::RegRel { reg, offset, subfield_offset: sub16 });
                    }
                }
            }
            (Base::Breg(reg, off), true) if !has_piece => {
                if let (Ok(base_offset), Ok(udt_offset)) =
                    (i32::try_from(off), i32::try_from(post_offset))
                {
                    out.push(CvLocation::RegRelIndir { reg, base_offset, udt_offset });
                }
            }
            _ => {}
        }

        if let Some(size) = piece_size {
            byte_offset = byte_offset.saturating_add(size);
        }
    }
    out
}

fn read_uleb(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0u32;
    for (n, &byte) in bytes.iter().enumerate() {
        if shift >= 64 {
            return None;
        }
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, n + 1));
        }
        shift += 7;
    }
    None
}

fn read_sleb(bytes: &[u8]) -> Option<(i64, usize)> {
    let mut value = 0i64;
    let mut shift = 0u32;
    for (n, &byte) in bytes.iter().enumerate() {
        if shift >= 64 {
            return None;
        }
        value |= i64::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            if shift < 64 && (byte & 0x40) != 0 {
                value |= !0i64 << shift;
            }
            return Some((value, n + 1));
        }
    }
    None
}

/// Encodes an unsigned integer into `S_INLINESITE` binary annotation format (1, 2, or 4 bytes,
/// big-endian with prefix bits, matching LLVM `GetCompressedAnnotation`).
pub(crate) fn encode_compressed_u32(out: &mut Vec<u8>, value: u32) {
    if value < 0x80 {
        out.push(value as u8);
    } else if value < 0x4000 {
        out.push(((value >> 8) as u8) | 0x80);
        out.push((value & 0xff) as u8);
    } else {
        let clamped = value & 0x1fff_ffff;
        out.push(((clamped >> 24) as u8) | 0xc0);
        out.push(((clamped >> 16) & 0xff) as u8);
        out.push(((clamped >> 8) & 0xff) as u8);
        out.push((clamped & 0xff) as u8);
    }
}

/// Encodes a signed delta for `ChangeLineOffset` (sign-magnitude with sign in bit 0, matching
/// LLVM `DecodeSignedOperand`).
pub(crate) fn encode_signed_annotation(out: &mut Vec<u8>, value: i32) {
    let encoded = if value < 0 {
        (value.unsigned_abs() << 1) | 1
    } else {
        (value as u32) << 1
    };
    encode_compressed_u32(out, encoded);
}

/// Decodes one compressed unsigned integer from `S_INLINESITE` binary annotations, advancing
/// `bytes`. Returns `None` on EOF or invalid encoding.
pub(crate) fn decode_compressed_u32(bytes: &mut &[u8]) -> Option<u32> {
    let (&first, rest) = bytes.split_first()?;
    if first & 0x80 == 0 {
        *bytes = rest;
        return Some(u32::from(first));
    }
    if first & 0xc0 == 0x80 {
        let (&second, rest) = rest.split_first()?;
        *bytes = rest;
        return Some((u32::from(first & 0x3f) << 8) | u32::from(second));
    }
    if first & 0xe0 == 0xc0 {
        if rest.len() < 3 {
            return None;
        }
        let val = (u32::from(first & 0x1f) << 24)
            | (u32::from(rest[0]) << 16)
            | (u32::from(rest[1]) << 8)
            | u32::from(rest[2]);
        *bytes = &rest[3..];
        return Some(val);
    }
    None
}

/// Decodes a signed binary annotation operand (inverse of [`encode_signed_annotation`]).
pub(crate) fn decode_signed_operand(encoded: u32) -> i32 {
    if encoded & 1 != 0 {
        -((encoded >> 1) as i32)
    } else {
        (encoded >> 1) as i32
    }
}

/// Encodes inlinee source line spans `(code_start, code_len, file_checksum_offset, line)` into
/// `S_INLINESITE` binary annotations relative to `(base_file_offset, base_line)`.
pub(crate) fn encode_inline_annotations(
    base_file: u32,
    base_line: u32,
    spans: &[(u32, u32, u32, u32)],
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cur_code: u32 = 0;
    let mut cur_file: u32 = base_file;
    let mut cur_line: i64 = i64::from(base_line);
    for &(start, len, file, line) in spans {
        if len == 0 {
            continue;
        }
        if file != cur_file {
            encode_compressed_u32(&mut out, BA_CHANGE_FILE);
            encode_compressed_u32(&mut out, file);
            cur_file = file;
        }
        let target_line = i64::from(line);
        let line_delta = target_line - cur_line;
        if line_delta != 0
            && let Ok(delta) = i32::try_from(line_delta)
        {
            encode_compressed_u32(&mut out, BA_CHANGE_LINE_OFFSET);
            encode_signed_annotation(&mut out, delta);
            cur_line = target_line;
        }
        if start >= cur_code {
            let code_delta = start - cur_code;
            if code_delta != 0 {
                encode_compressed_u32(&mut out, BA_CHANGE_CODE_OFFSET);
                encode_compressed_u32(&mut out, code_delta);
            }
        } else {
            encode_compressed_u32(&mut out, BA_CODE_OFFSET);
            encode_compressed_u32(&mut out, start);
        }
        encode_compressed_u32(&mut out, BA_CHANGE_CODE_LENGTH);
        encode_compressed_u32(&mut out, len);
        cur_code = start.saturating_add(len);
    }
    out.push(0); // Eof
    out
}

/// Remaps `BA_CHANGE_FILE` checksum offsets inside an existing `S_INLINESITE` binary
/// annotation byte slice (used when merging C/C++ objects' `.debug$S`).
pub(crate) fn remap_inline_annotations(
    mut data: &[u8],
    mut map_file: impl FnMut(u32) -> u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    while !data.is_empty() {
        let Some(op) = decode_compressed_u32(&mut data) else { break };
        if op == BA_EOF {
            out.push(0);
            break;
        }
        encode_compressed_u32(&mut out, op);
        match op {
            BA_CHANGE_FILE => {
                let Some(file) = decode_compressed_u32(&mut data) else { break };
                encode_compressed_u32(&mut out, map_file(file));
            }
            BA_CODE_OFFSET
            | BA_CHANGE_CODE_OFFSET_BASE
            | BA_CHANGE_CODE_OFFSET
            | BA_CHANGE_CODE_LENGTH
            | BA_CHANGE_LINE_OFFSET
            | BA_CHANGE_LINE_END_DELTA
            | BA_CHANGE_RANGE_KIND
            | BA_CHANGE_COLUMN_START
            | BA_CHANGE_COLUMN_END_DELTA
            | BA_CHANGE_CODE_OFFSET_AND_LINE_OFFSET
            | BA_CHANGE_COLUMN_END => {
                let Some(v) = decode_compressed_u32(&mut data) else { break };
                encode_compressed_u32(&mut out, v);
            }
            BA_CHANGE_CODE_LENGTH_AND_CODE_OFFSET => {
                let Some(v1) = decode_compressed_u32(&mut data) else { break };
                let Some(v2) = decode_compressed_u32(&mut data) else { break };
                encode_compressed_u32(&mut out, v1);
                encode_compressed_u32(&mut out, v2);
            }
            _ => break,
        }
    }
    out
}
