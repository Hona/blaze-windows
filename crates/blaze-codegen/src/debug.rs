//! Per-function debug information shared between the code generator and the linker: the
//! types, scopes, parameters, locals and inlined calls of a compiled function, independent of
//! where the function is placed in an image.
//!
//! Written once when a function is compiled (inside its side table in the store) and consumed
//! when the linker builds or patches debug info (such as a PE image's PDB).

use blaze_format::SpanRef;
use serde::{Deserialize, Serialize};

/// A type in a [`FunctionDebug::types`] table, by index.
pub type TypeIndex = u32;

/// How the bytes of a primitive [`DebugType::Base`] are interpreted.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum BaseEncoding {
    Bool,
    Char,
    Signed,
    Unsigned,
    Float,
}

impl BaseEncoding {
    /// From a DWARF `DW_ATE_*` encoding byte (`hir-ty-codegen/debuginfo/types.rs`).
    pub const fn from_dwarf(encoding: u8) -> Option<BaseEncoding> {
        match encoding {
            0x02 => Some(BaseEncoding::Bool),
            0x04 => Some(BaseEncoding::Float),
            0x05 => Some(BaseEncoding::Signed),
            0x07 => Some(BaseEncoding::Unsigned),
            0x10 => Some(BaseEncoding::Char),
            _ => None,
        }
    }

    /// To its DWARF `DW_ATE_*` encoding byte.
    pub const fn to_dwarf(self) -> u8 {
        match self {
            BaseEncoding::Bool => 0x02,
            BaseEncoding::Float => 0x04,
            BaseEncoding::Signed => 0x05,
            BaseEncoding::Unsigned => 0x07,
            BaseEncoding::Char => 0x10,
        }
    }
}

/// A type description self-contained within a slice of [`DebugType`]s: composite types name
/// their fields' and elements' types by [`TypeIndex`] in the same slice, so cyclic types
/// (through pointers) are represented directly.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Debug)] // clone: per-function debug record
pub enum DebugType {
    /// A primitive scalar: integers, floats, `bool`, `char`.
    Base { name: String, size: u64, encoding: BaseEncoding },
    /// A 64-bit thin pointer or reference (`&T`, `&mut T`, `*const T`, `*mut T`, `Box<T>`).
    /// `to` is `None` when the pointee is opaque or past the pointer-following depth.
    Pointer { name: String, to: Option<TypeIndex> },
    /// A fixed-size array `[T; len]`.
    Array { of: TypeIndex, len: u64 },
    /// A struct, tuple, closure, wide pointer (`&str`, `&[T]` as `{ data_ptr, length }`,
    /// `&dyn Trait` as `{ pointer, vtable }`), or opaque aggregate.
    Struct(Aggregate),
    /// A Rust `union`.
    Union(Aggregate),
    /// A fieldless C-like enum: an integer discriminant with named values.
    Names { name: String, size: u64, names: Vec<(String, u64)> },
    /// A Rust enum with data (or a coroutine state machine). `tag` is `None` for single-variant
    /// enums that carry no discriminant.
    Enum { of: Aggregate, tag: Option<EnumTag>, variants: Vec<EnumVariant> },
}

impl DebugType {
    /// The byte size of `types[index]`, guarding against malformed cycles.
    pub fn byte_size(types: &[DebugType], index: TypeIndex, pointer_bytes: u64) -> u64 {
        fn size_of(
            types: &[DebugType],
            index: TypeIndex,
            pointer_bytes: u64,
            depth: u32,
        ) -> u64 {
            if depth >= 64 {
                return 0;
            }
            match types.get(index as usize) {
                Some(DebugType::Base { size, .. })
                | Some(DebugType::Names { size, .. }) => *size,
                Some(DebugType::Pointer { .. }) => pointer_bytes,
                Some(DebugType::Struct(it))
                | Some(DebugType::Union(it))
                | Some(DebugType::Enum { of: it, .. }) => it.size,
                Some(DebugType::Array { of, len }) => {
                    size_of(types, *of, pointer_bytes, depth + 1).saturating_mul(*len)
                }
                None => 0,
            }
        }
        size_of(types, index, pointer_bytes, 0)
    }
}

/// Name, total byte size, and fields of a struct, union, or enum outer layout.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Debug)] // clone: inside `DebugType`
pub struct Aggregate {
    pub name: String,
    pub size: u64,
    pub fields: Vec<Field>,
}

/// One field of a struct, union, tuple, or enum variant.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Debug)] // clone: inside `Aggregate`/`EnumVariant`
pub struct Field {
    pub name: String,
    pub offset: u64,
    pub ty: TypeIndex,
}

/// Where an enum stores its discriminant tag: an unsigned integer of `size` bytes at `offset`.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct EnumTag {
    pub offset: u64,
    pub size: u64,
    /// True for coroutine/async state machines (states named `Unresumed`, `Suspend0`, ...).
    pub states: bool,
}

/// One variant of a [`DebugType::Enum`]. `tag` is `Some(value)` for explicitly tagged variants
/// and `None` for the untagged niche variant (or sole variant of a single-variant enum).
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Debug)] // clone: inside `DebugType`
pub struct EnumVariant {
    pub name: String,
    pub tag: Option<u64>,
    pub fields: Vec<Field>,
}

/// A lexical scope within a function, enclosing inner scopes and locals.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Debug)] // clone: inside `FunctionDebug`
pub struct Scope {
    /// Enclosing scope index in [`FunctionDebug::scopes`], or `None` for top-level.
    pub parent: Option<u32>,
    /// Half-open code offset ranges `[from, to)` relative to the function start.
    pub ranges: Vec<(u32, u32)>,
}

/// Where a local variable or parameter lives while its function runs.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Debug)] // clone: inside `Local`
pub enum LocalPlace {
    /// At a fixed signed offset from [`FunctionDebug::frame_base`] for its whole scope.
    Frame(i64),
    /// Described by DWARF location expressions over half-open code offset ranges `[from, to)`.
    Ranges(Vec<(u32, u32, Vec<u8>)>),
}

/// A named parameter or local variable of a function.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Debug)] // clone: inside `FunctionDebug`
pub struct Local {
    pub name: String,
    pub param: bool,
    /// Index into [`FunctionDebug::types`], or `None` when the type is unknown.
    pub ty: Option<TypeIndex>,
    pub place: LocalPlace,
    /// Index into [`FunctionDebug::scopes`], or `None` for the whole function.
    pub scope: Option<u32>,
}

/// An inlined callee frame inside a function, nested via `parent` when inlined inside another
/// inlined call.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Hash, Debug)] // clone: inside `FunctionDebug`
pub struct InlinedSite {
    /// Enclosing inlined site index in [`FunctionDebug::inlined`], or `None` for top-level.
    pub parent: Option<u32>,
    /// Demangled name of the inlined function or closure.
    pub callee: String,
    /// Where the call was written (in the parent inlinee, or in the outer function).
    pub call_site: SpanRef,
    /// Where the inlinee was declared (file and starting line for `DEBUG_S_INLINEELINES`).
    pub decl: Option<SpanRef>,
    /// Half-open code offset ranges `[from, to)` covered by this inlinee and its nested calls.
    pub ranges: Vec<(u32, u32)>,
}

/// Complete per-function debug metadata beyond line rows: frame base, types, lexical scopes,
/// named locals/parameters, and inlined call sites.
#[derive(Serialize, Deserialize, Clone, Default, PartialEq, Eq, Hash, Debug)] // clone: stored per function in linker state
pub struct FunctionDebug {
    /// DWARF expression for the frame base register (for example `[DW_OP_reg6]` = RBP on x64).
    pub frame_base: Vec<u8>,
    /// Self-contained type table referenced by [`Local::ty`].
    pub types: Vec<DebugType>,
    /// Lexical scopes, parents before children.
    pub scopes: Vec<Scope>,
    /// Named parameters and local variables.
    pub locals: Vec<Local>,
    /// Inlined calls, outer before inner.
    pub inlined: Vec<InlinedSite>,
}

impl FunctionDebug {
    pub fn is_empty(&self) -> bool {
        self.locals.is_empty() && self.inlined.is_empty()
    }
}
