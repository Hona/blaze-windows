//! Content-deduplicated CodeView TPI/IPI type table builder and Rust [`DebugType`] lowering.
//!
//! Records are append-only: existing `TypeIndex`es never move, so incremental PDB patches that
//! introduce no new types leave the TPI, IPI and hash streams untouched, and patches that add
//! new types append only the new records and update the 56-byte stream header and hash stream.

use std::alloc::Global;

use blaze_codegen::debug::{Aggregate, DebugType, EnumTag, EnumVariant, Field};
use blaze_hash::HashMap;
use smallvec::SmallVec;

use super::cv;

/// Byte interval between entries in the TPI/IPI `IndexOffsetBuffer` (8 KiB, matching LLVM).
const INDEX_OFFSET_STRIDE: u32 = 8192;

/// Maximum body size of one `LF_FIELDLIST` chunk before splitting with `LF_INDEX` continuation.
/// Well below the 65,534-byte CodeView `u16` record length limit.
const MAX_FIELDLIST_BYTES: usize = 60_000;

/// An append-only, content-deduplicated CodeView type or item-ID stream (TPI or IPI).
#[derive(Clone, Default)] // clone: tests / model snapshots
pub(crate) struct TypeTable {
    /// Concatenated 4-byte-aligned records (`[len: u16, kind: u16, body..., pad...]`).
    records: Vec<u8>,
    /// Start byte offset in `records` for each `TypeIndex` (`index = ti - 0x1000`).
    offsets: Vec<u32>,
    /// Hash bucket (`hash_type_record(rec) % TPI_HASH_BUCKETS`) per record.
    hashes: Vec<u32>,
    /// `(TypeIndex, byte_offset)` checkpoints every ~8 KiB for O(log N) random access.
    index_offsets: Vec<(u32, u32)>,
    /// Content hash -> candidate array indices (`ti - 0x1000`) into `records`.
    dedup: HashMap<u64, SmallVec<[u32; 2]>, Global>,
}

impl TypeTable {
    pub(crate) fn new() -> TypeTable {
        TypeTable {
            records: Vec::new(),
            offsets: Vec::new(),
            hashes: Vec::new(),
            index_offsets: Vec::new(),
            dedup: HashMap::new_in(Global),
        }
    }

    /// Number of type records currently in this table.
    pub(crate) fn count(&self) -> u32 {
        self.offsets.len() as u32
    }

    /// Total byte length of serialized type records (excluding the 56-byte TPI/IPI header).
    pub(crate) fn record_bytes(&self) -> usize {
        self.records.len()
    }

    /// Raw bytes of record `ti` (`>= 0x1000`), including its 2-byte length and 2-byte kind.
    pub(crate) fn record(&self, ti: u32) -> Option<&[u8]> {
        let idx = ti.checked_sub(cv::FIRST_NON_SIMPLE)? as usize;
        let start = *self.offsets.get(idx)? as usize;
        let end = self.offsets.get(idx + 1).map_or(self.records.len(), |&v| v as usize);
        Some(&self.records[start..end])
    }

    /// Interns a complete, 4-byte-aligned CodeView type record `[len: u16, kind: u16, body...]`,
    /// deduplicating by exact bytes, and returns its `TypeIndex` (`>= 0x1000`).
    pub(crate) fn intern_raw(&mut self, record: &[u8]) -> u32 {
        debug_assert!(record.len() >= 4 && record.len() % 4 == 0);
        let key = content_hash(record);
        if let Some(bucket) = self.dedup.get(&key) {
            for &idx in bucket {
                let start = self.offsets[idx as usize] as usize;
                let end =
                    self.offsets.get(idx as usize + 1).map_or(self.records.len(), |&v| v as usize);
                if &self.records[start..end] == record {
                    return cv::FIRST_NON_SIMPLE + idx;
                }
            }
        }
        let idx = self.offsets.len() as u32;
        let ti = cv::FIRST_NON_SIMPLE + idx;
        let start = self.records.len() as u32;
        if self.index_offsets.last().is_none_or(|&(_, prev)| start - prev >= INDEX_OFFSET_STRIDE) {
            self.index_offsets.push((ti, start));
        }
        self.offsets.push(start);
        self.records.extend_from_slice(record);
        self.hashes.push(cv::hash_type_record(record) % cv::TPI_HASH_BUCKETS);
        self.dedup.entry(key).or_default().push(idx);
        ti
    }

    /// Encodes a record with `kind` and `fill(body)`, pads it with `LF_PADn` to 4 bytes,
    /// interns it, and returns its `TypeIndex`.
    pub(crate) fn intern(&mut self, kind: u16, fill: impl FnOnce(&mut Vec<u8>)) -> u32 {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&[0, 0]);
        buf.extend_from_slice(&kind.to_le_bytes());
        fill(&mut buf);
        cv::pad_type(&mut buf);
        let len = (buf.len() - 2) as u16;
        buf[0..2].copy_from_slice(&len.to_le_bytes());
        self.intern_raw(&buf)
    }

    /// Builds the 56-byte TPI/IPI stream header for this table pointing at `hash_stream`.
    pub(crate) fn header(&self, hash_stream: u16) -> [u8; 56] {
        let hash_val_len = self.hashes.len() as u32 * 4;
        let idx_off_len = self.index_offsets.len() as u32 * 8;
        let hash_adj_off = hash_val_len + idx_off_len;
        let mut out = [0u8; 56];
        out[0..4].copy_from_slice(&20040203u32.to_le_bytes()); // PdbTpiV80
        out[4..8].copy_from_slice(&56u32.to_le_bytes());
        out[8..12].copy_from_slice(&cv::FIRST_NON_SIMPLE.to_le_bytes());
        out[12..16].copy_from_slice(&(cv::FIRST_NON_SIMPLE + self.count()).to_le_bytes());
        out[16..20].copy_from_slice(&(self.records.len() as u32).to_le_bytes());
        out[20..22].copy_from_slice(&hash_stream.to_le_bytes());
        out[22..24].copy_from_slice(&0xffffu16.to_le_bytes()); // no aux hash stream
        out[24..28].copy_from_slice(&4u32.to_le_bytes()); // hash key size
        out[28..32].copy_from_slice(&cv::TPI_HASH_BUCKETS.to_le_bytes());
        out[32..36].copy_from_slice(&0u32.to_le_bytes()); // HashValueBuffer.Off
        out[36..40].copy_from_slice(&hash_val_len.to_le_bytes());
        out[40..44].copy_from_slice(&hash_val_len.to_le_bytes()); // IndexOffsetBuffer.Off
        out[44..48].copy_from_slice(&idx_off_len.to_le_bytes());
        out[48..52].copy_from_slice(&hash_adj_off.to_le_bytes()); // HashAdjBuffer.Off
        out[52..56].copy_from_slice(&0u32.to_le_bytes()); // HashAdjBuffer.Length
        out
    }

    /// Serializes the full TPI/IPI stream (56-byte header + all records).
    pub(crate) fn stream_bytes(&self, hash_stream: u16) -> Vec<u8> {
        let mut out = Vec::with_capacity(56 + self.records.len());
        out.extend_from_slice(&self.header(hash_stream));
        out.extend_from_slice(&self.records);
        out
    }

    /// Serializes the companion hash stream (`HashValueBuffer` + `IndexOffsetBuffer`).
    pub(crate) fn hash_stream_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.hashes.len() * 4 + self.index_offsets.len() * 8);
        for &h in &self.hashes {
            out.extend_from_slice(&h.to_le_bytes());
        }
        for &(ti, off) in &self.index_offsets {
            out.extend_from_slice(&ti.to_le_bytes());
            out.extend_from_slice(&off.to_le_bytes());
        }
        out
    }

    /// Appended record bytes since `prev_record_bytes` (for incremental patching).
    pub(crate) fn tail_since(&self, prev_record_bytes: usize) -> &[u8] {
        &self.records[prev_record_bytes..]
    }

    /// Interns an `LF_ARGLIST` + `LF_PROCEDURE` pair and returns the procedure's `TypeIndex`.
    pub(crate) fn intern_procedure(&mut self, ret: u32, params: &[u32]) -> u32 {
        let arg_list = self.intern(cv::LF_ARGLIST, |out| {
            out.extend_from_slice(&(params.len() as u32).to_le_bytes());
            for &p in params {
                out.extend_from_slice(&p.to_le_bytes());
            }
        });
        self.intern(cv::LF_PROCEDURE, |out| {
            out.extend_from_slice(&ret.to_le_bytes());
            out.push(0); // NearC
            out.push(0); // FunctionOptions::None
            out.extend_from_slice(&(params.len().min(usize::from(u16::MAX)) as u16).to_le_bytes());
            out.extend_from_slice(&arg_list.to_le_bytes());
        })
    }

    /// Interns an `LF_FUNC_ID` in an IPI table, naming `name` with TPI procedure type `func_type`.
    pub(crate) fn intern_func_id(&mut self, func_type: u32, name: &str) -> u32 {
        self.intern(cv::LF_FUNC_ID, |out| {
            out.extend_from_slice(&0u32.to_le_bytes()); // global scope
            out.extend_from_slice(&func_type.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.push(0);
        })
    }

    /// Approximate heap bytes held by this table.
    pub(crate) fn held(&self) -> usize {
        self.records.capacity()
            + self.offsets.capacity() * size_of::<u32>()
            + self.hashes.capacity() * size_of::<u32>()
            + self.index_offsets.capacity() * size_of::<(u32, u32)>()
    }
}

/// Fast 64-bit FNV-1a hash over a record's bytes for deduplication lookup (deterministic; exact
/// equality is always verified against the stored record slice).
fn content_hash(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Lowers a self-contained slice of Rust [`DebugType`]s into CodeView records in `tpi`,
/// returning one CodeView `TypeIndex` per entry in `types`.
///
/// Acyclic types are emitted bottom-up so pointers reference complete definitions directly.
/// Cycles (for example `struct Node { next: Option<Box<Node>> }`) break via an `LF_STRUCTURE`
/// / `LF_UNION` forward reference, followed by the complete definition once its fields finish.
pub(crate) fn lower_rust_types(tpi: &mut TypeTable, types: &[DebugType]) -> Vec<u32> {
    let mut lowerer = Lowerer {
        tpi,
        types,
        done: vec![None; types.len()],
        fwd: vec![None; types.len()],
        visiting: vec![false; types.len()],
    };
    for i in 0..types.len() {
        lowerer.lower(i);
    }
    lowerer.done.into_iter().map(|it| it.unwrap_or(cv::T_VOID)).collect()
}

struct Lowerer<'a> {
    tpi: &'a mut TypeTable,
    types: &'a [DebugType],
    done: Vec<Option<u32>>,
    fwd: Vec<Option<u32>>,
    visiting: Vec<bool>,
}

impl Lowerer<'_> {
    fn lower(&mut self, index: usize) -> u32 {
        if let Some(ti) = self.done.get(index).copied().flatten() {
            return ti;
        }
        let Some(ty) = self.types.get(index) else {
            return cv::T_VOID;
        };
        if self.visiting[index] {
            return self.forward_ref(index);
        }
        self.visiting[index] = true;
        let ti = match ty {
            DebugType::Base { encoding, size, .. } => cv::primitive_type(*encoding, *size),
            DebugType::Pointer { to, .. } => {
                let pointee = to.map_or(cv::T_VOID, |idx| self.lower(idx as usize));
                self.tpi.intern(cv::LF_POINTER, |out| {
                    out.extend_from_slice(&pointee.to_le_bytes());
                    out.extend_from_slice(&cv::PTR64_ATTRS.to_le_bytes());
                })
            }
            DebugType::Array { of, len } => {
                let elem = self.lower(*of as usize);
                let byte_size = DebugType::byte_size(self.types, index as u32, 8);
                let _ = len; // encoded via total byte_size in CodeView LF_ARRAY
                self.tpi.intern(cv::LF_ARRAY, |out| {
                    out.extend_from_slice(&elem.to_le_bytes());
                    out.extend_from_slice(&cv::T_UINT8.to_le_bytes()); // usize index
                    cv::write_numeric_u64(out, byte_size);
                    out.push(0); // empty name
                })
            }
            DebugType::Struct(agg) => self.lower_struct(agg, 0),
            DebugType::Union(agg) => self.lower_union(agg),
            DebugType::Names { name, size, names } => self.lower_fieldless_enum(name, *size, names, 0),
            DebugType::Enum { of, tag, variants } => self.lower_rust_enum(of, *tag, variants),
        };
        self.visiting[index] = false;
        self.done[index] = Some(ti);
        ti
    }

    fn forward_ref(&mut self, index: usize) -> u32 {
        if let Some(ti) = self.fwd[index] {
            return ti;
        }
        let ti = match &self.types[index] {
            DebugType::Struct(agg) => self.emit_struct_record(&agg.name, 0, cv::OPT_FORWARD_REF, 0, 0),
            DebugType::Union(agg) => self.emit_union_record(&agg.name, 0, cv::OPT_FORWARD_REF, 0, 0),
            DebugType::Enum { of, tag: Some(_), .. } => {
                self.emit_union_record(&of.name, 0, cv::OPT_FORWARD_REF, 0, 0)
            }
            DebugType::Enum { of, tag: None, .. } => {
                self.emit_struct_record(&of.name, 0, cv::OPT_FORWARD_REF, 0, 0)
            }
            DebugType::Names { name, size, .. } => {
                let underlying = cv::enum_underlying_type(*size);
                self.tpi.intern(cv::LF_ENUM, |out| {
                    out.extend_from_slice(&0u16.to_le_bytes());
                    out.extend_from_slice(&cv::OPT_FORWARD_REF.to_le_bytes());
                    out.extend_from_slice(&underlying.to_le_bytes());
                    out.extend_from_slice(&0u32.to_le_bytes());
                    out.extend_from_slice(name.as_bytes());
                    out.push(0);
                })
            }
            _ => cv::T_VOID,
        };
        self.fwd[index] = Some(ti);
        ti
    }

    fn lower_struct(&mut self, agg: &Aggregate, extra_props: u16) -> u32 {
        let members: Vec<Vec<u8>> = agg
            .fields
            .iter()
            .map(|f| {
                let ty = self.lower(f.ty as usize);
                encode_member(&f.name, ty, f.offset)
            })
            .collect();
        let field_list = emit_fieldlist(self.tpi, &members);
        let count = agg.fields.len().min(usize::from(u16::MAX)) as u16;
        self.emit_struct_record(&agg.name, count, extra_props, field_list, agg.size)
    }

    fn lower_union(&mut self, agg: &Aggregate) -> u32 {
        let members: Vec<Vec<u8>> = agg
            .fields
            .iter()
            .map(|f| {
                let ty = self.lower(f.ty as usize);
                encode_member(&f.name, ty, f.offset)
            })
            .collect();
        let field_list = emit_fieldlist(self.tpi, &members);
        let count = agg.fields.len().min(usize::from(u16::MAX)) as u16;
        self.emit_union_record(&agg.name, count, 0, field_list, agg.size)
    }

    fn lower_fieldless_enum(
        &mut self,
        name: &str,
        size: u64,
        names: &[(String, u64)],
        extra_props: u16,
    ) -> u32 {
        let members: Vec<Vec<u8>> = names
            .iter()
            .map(|(variant_name, value)| encode_enumerate(variant_name, *value))
            .collect();
        let field_list = emit_fieldlist(self.tpi, &members);
        let underlying = cv::enum_underlying_type(size);
        let count = names.len().min(usize::from(u16::MAX)) as u16;
        self.tpi.intern(cv::LF_ENUM, |out| {
            out.extend_from_slice(&count.to_le_bytes());
            out.extend_from_slice(&extra_props.to_le_bytes());
            out.extend_from_slice(&underlying.to_le_bytes());
            out.extend_from_slice(&field_list.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
            out.push(0);
        })
    }

    /// Lowers a Rust enum with data in rustc's MSVC C++-like layout:
    /// - Single-variant enum (`tag == None`): `LF_STRUCTURE` with the variant's fields.
    /// - Multi-variant enum (`tag == Some(tag)`):
    ///   - nested `LF_ENUM` `<Name>::Discriminant` listing tagged variants;
    ///   - one nested `LF_STRUCTURE` `<Name>::<Variant>` per variant with `tag` at `tag.offset`
    ///     plus all payload fields at their byte offsets;
    ///   - outer `LF_UNION` `<Name>` containing `tag` (directly when `tag.offset == 0`, or via
    ///     nested `<Name>::Tag` when `tag.offset > 0`), one member per variant, and `LF_NESTTYPE`
    ///     entries linking the nested discriminant and variant structs.
    fn lower_rust_enum(
        &mut self,
        of: &Aggregate,
        tag: Option<EnumTag>,
        variants: &[EnumVariant],
    ) -> u32 {
        let Some(tag) = tag else {
            let fields: &[Field] = variants.first().map_or(&[], |v| v.fields.as_slice());
            let members: Vec<Vec<u8>> = fields
                .iter()
                .map(|f| {
                    let ty = self.lower(f.ty as usize);
                    encode_member(&f.name, ty, f.offset)
                })
                .collect();
            let field_list = emit_fieldlist(self.tpi, &members);
            let count = fields.len().min(usize::from(u16::MAX)) as u16;
            return self.emit_struct_record(&of.name, count, 0, field_list, of.size);
        };

        let discr_values: Vec<(String, u64)> = variants
            .iter()
            .filter_map(|v| Some((v.name.clone(), v.tag?)))
            .collect();
        let discr_name = format!("{}::Discriminant", of.name);
        let discr_ti = if discr_values.is_empty() {
            cv::enum_underlying_type(tag.size)
        } else {
            self.lower_fieldless_enum(&discr_name, tag.size, &discr_values, cv::OPT_NESTED)
        };

        let mut union_members: Vec<Vec<u8>> = Vec::with_capacity(variants.len() * 2 + 2);
        if !discr_values.is_empty() {
            union_members.push(encode_nesttype("Discriminant", discr_ti));
        }

        // Expose `tag` directly at offset 0 of the union when `tag.offset == 0`, or via a
        // nested `Tag` layout struct at offset 0 when the niche/tag sits at a non-zero offset.
        if tag.offset == 0 {
            union_members.push(encode_member("tag", discr_ti, 0));
        } else {
            let tag_struct_name = format!("{}::$Tag", of.name);
            let tag_fields = [encode_member("tag", discr_ti, tag.offset)];
            let tag_fl = emit_fieldlist(self.tpi, &tag_fields);
            let tag_struct_ti =
                self.emit_struct_record(&tag_struct_name, 1, cv::OPT_NESTED, tag_fl, of.size);
            union_members.push(encode_nesttype("$Tag", tag_struct_ti));
            union_members.push(encode_member("tag", tag_struct_ti, 0));
        }

        for variant in variants {
            let mut v_members: Vec<Vec<u8>> = Vec::with_capacity(variant.fields.len() + 1);
            v_members.push(encode_member("tag", discr_ti, tag.offset));
            for field in &variant.fields {
                let field_ti = self.lower(field.ty as usize);
                v_members.push(encode_member(&field.name, field_ti, field.offset));
            }
            let v_fl = emit_fieldlist(self.tpi, &v_members);
            let v_full_name = format!("{}::{}", of.name, variant.name);
            let v_count = v_members.len().min(usize::from(u16::MAX)) as u16;
            let v_ti = self.emit_struct_record(&v_full_name, v_count, cv::OPT_NESTED, v_fl, of.size);
            union_members.push(encode_nesttype(&variant.name, v_ti));
            union_members.push(encode_member(&variant.name, v_ti, 0));
        }

        let field_list = emit_fieldlist(self.tpi, &union_members);
        let count = union_members.len().min(usize::from(u16::MAX)) as u16;
        self.emit_union_record(&of.name, count, cv::OPT_CONTAINS_NESTED, field_list, of.size)
    }

    fn emit_struct_record(
        &mut self,
        name: &str,
        count: u16,
        props: u16,
        field_list: u32,
        size: u64,
    ) -> u32 {
        self.tpi.intern(cv::LF_STRUCTURE, |out| {
            out.extend_from_slice(&count.to_le_bytes());
            out.extend_from_slice(&props.to_le_bytes());
            out.extend_from_slice(&field_list.to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes()); // derived
            out.extend_from_slice(&0u32.to_le_bytes()); // vshape
            cv::write_numeric_u64(out, size);
            out.extend_from_slice(name.as_bytes());
            out.push(0);
        })
    }

    fn emit_union_record(
        &mut self,
        name: &str,
        count: u16,
        props: u16,
        field_list: u32,
        size: u64,
    ) -> u32 {
        self.tpi.intern(cv::LF_UNION, |out| {
            out.extend_from_slice(&count.to_le_bytes());
            out.extend_from_slice(&props.to_le_bytes());
            out.extend_from_slice(&field_list.to_le_bytes());
            cv::write_numeric_u64(out, size);
            out.extend_from_slice(name.as_bytes());
            out.push(0);
        })
    }
}

/// Encodes an `LF_MEMBER` sub-record, 4-byte padded with `LF_PADn`.
fn encode_member(name: &str, field_type: u32, offset: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + name.len());
    out.extend_from_slice(&cv::LF_MEMBER.to_le_bytes());
    out.extend_from_slice(&cv::ACCESS_PUBLIC.to_le_bytes());
    out.extend_from_slice(&field_type.to_le_bytes());
    cv::write_numeric_u64(&mut out, offset);
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    cv::pad_type(&mut out);
    out
}

/// Encodes an `LF_ENUMERATE` sub-record, 4-byte padded with `LF_PADn`.
fn encode_enumerate(name: &str, value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + name.len());
    out.extend_from_slice(&cv::LF_ENUMERATE.to_le_bytes());
    out.extend_from_slice(&cv::ACCESS_PUBLIC.to_le_bytes());
    cv::write_numeric_u64(&mut out, value);
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    cv::pad_type(&mut out);
    out
}

/// Encodes an `LF_NESTTYPE` sub-record, 4-byte padded with `LF_PADn`.
fn encode_nesttype(name: &str, nested_type: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + name.len());
    out.extend_from_slice(&cv::LF_NESTTYPE.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // padding
    out.extend_from_slice(&nested_type.to_le_bytes());
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    cv::pad_type(&mut out);
    out
}

/// Emits one or more `LF_FIELDLIST` records (chaining via `LF_INDEX` if `members` exceed
/// [`MAX_FIELDLIST_BYTES`]). Returns `0` when `members` is empty.
fn emit_fieldlist(tpi: &mut TypeTable, members: &[Vec<u8>]) -> u32 {
    if members.is_empty() {
        return 0;
    }
    // Split into chunks under MAX_FIELDLIST_BYTES, then emit tail-first so each LF_INDEX
    // points to an already-interned smaller TypeIndex (CodeView topological order).
    let mut chunks: Vec<std::ops::Range<usize>> = Vec::new();
    let mut start = 0;
    let mut size = 0;
    for (i, m) in members.iter().enumerate() {
        if i > start && size + m.len() + 8 > MAX_FIELDLIST_BYTES {
            chunks.push(start..i);
            start = i;
            size = 0;
        }
        size += m.len();
    }
    chunks.push(start..members.len());

    let mut next_ti: Option<u32> = None;
    for range in chunks.into_iter().rev() {
        let cont = next_ti;
        let ti = tpi.intern(cv::LF_FIELDLIST, |out| {
            for m in &members[range] {
                out.extend_from_slice(m);
            }
            if let Some(cont_ti) = cont {
                out.extend_from_slice(&cv::LF_INDEX.to_le_bytes());
                out.extend_from_slice(&0u16.to_le_bytes()); // pad
                out.extend_from_slice(&cont_ti.to_le_bytes());
            }
        });
        next_ti = Some(ti);
    }
    next_ti.unwrap_or(0)
}
