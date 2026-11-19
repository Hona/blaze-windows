//! An image as one record, so a daemon that starts again patches the file its last link left
//! instead of laying the image out from scratch ([`Image::checkpoint`], [`Image::restore`]).
//!
//! The record is the image's state as its last commit left it: every piece, where it is, its
//! fixups and what every symbol is ([`crate::state::State`]), the symbol tables in interning
//! order ([`crate::symbols::Symbols`]), and the natives' resolution ([`crate::native::Resolved`]).
//! The native inputs themselves are not in it: they are named by content, and the caller hands
//! their bytes back on restore, each read and checked again as a first link reads it. What the
//! image keeps only to start its next stage warm (its writer's last tables, its objects read,
//! its debug side file) is not in it either: the first stage after a restore builds those as it
//! would after they were let go.
//!
//! A restore is checked once, whole: the file the restored state makes must have the digest the
//! checkpoint recorded ([`crate::patch`]), and a record of another layout, another format or a
//! state no restore can rebuild is refused naming why. Nothing is read from the image's file on
//! the disk: the state holds every byte of it.
//!
//! The encoding is [`Wire`], one hand-written impl per type through [`wire_struct!`] and
//! [`wire_enum!`], which destructure without `..`: a field added to a type is a compile error
//! here until it is encoded. The generic `Persist` over `for const` (memory-and-data's
//! outputs-are-records) replaces these once it lands.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::Arc;

use blaze_codegen::{InstanceKey, Line, Made, plan::Origin};
use blaze_core::lock::Lock;
use blaze_format::SpanRef;
use blaze_format::cursor::{Put as _, Reader};
use blaze_ids::ContentId;
use blaze_items::ItemKey;

use crate::{Debug, Format, Image, LinkError, Output};

/// The record's first bytes, and the layout they name: a record of another layout is refused.
const MAGIC: &[u8; 8] = b"BLKIMG02";

/// A value as the checkpoint encodes it, and back.
pub(crate) trait Wire: Sized {
    fn put(&self, out: &mut Vec<u8>);
    fn take(r: &mut Reader<'_>) -> Result<Self, String>;
}

/// Each field of a struct in order, the struct destructured whole: a field added is a compile
/// error until it is listed.
macro_rules! wire_struct {
    ($ty:ident { $($field:ident),* $(,)? }) => {
        impl $crate::checkpoint::Wire for $ty {
            fn put(&self, out: &mut Vec<u8>) {
                let $ty { $($field),* } = self;
                $( $crate::checkpoint::Wire::put($field, out); )*
            }
            fn take(r: &mut blaze_format::cursor::Reader<'_>) -> Result<Self, String> {
                Ok($ty { $($field: $crate::checkpoint::Wire::take(r)?),* })
            }
        }
    };
}

/// An enum as a tag byte, then its variant's fields: every variant listed with its tag, so a
/// variant added is a compile error (a `match` that is not exhaustive) until it is.
macro_rules! wire_enum {
    ($ty:ident { $( $tag:literal => $var:ident $( ( $($t:ident),* ) )? $( { $($f:ident),* } )? ),* $(,)? }) => {
        impl $crate::checkpoint::Wire for $ty {
            #[allow(non_snake_case, unused_variables)]
            fn put(&self, out: &mut Vec<u8>) {
                match self {
                    $( $ty::$var $( ( $($t),* ) )? $( { $($f),* } )? => {
                        blaze_format::cursor::Put::put_u8(out, $tag);
                        $( $( $crate::checkpoint::Wire::put($t, out); )* )?
                        $( $( $crate::checkpoint::Wire::put($f, out); )* )?
                    } )*
                }
            }
            #[allow(non_snake_case, unused_variables)]
            fn take(r: &mut blaze_format::cursor::Reader<'_>) -> Result<Self, String> {
                let tag = r.u8().map_err(String::from)?;
                Ok(match tag {
                    $( $tag => $ty::$var
                        $( ( $( { let $t = $crate::checkpoint::Wire::take(r)?; $t } ),* ) )?
                        $( { $($f: $crate::checkpoint::Wire::take(r)?),* } )?, )*
                    // alloc: error path
                    other => return Err(format!(concat!("a ", stringify!($ty), " of tag {}, which no variant has"), other)),
                })
            }
        }
    };
}

pub(crate) use {wire_enum, wire_struct};

/// A count of elements each at least `each` bytes: never more than the bytes left hold, so a
/// torn or hostile count allocates nothing.
pub(crate) fn count(r: &mut Reader<'_>, each: usize) -> Result<usize, String> {
    r.count_u64(each.max(1)).map_err(String::from)
}

pub(crate) fn put_len(out: &mut Vec<u8>, len: usize) {
    out.put_u64(len as u64);
}

macro_rules! wire_int {
    ($($ty:ty => $put:ident, $take:ident);* $(;)?) => {$(
        impl Wire for $ty {
            #[inline]
            fn put(&self, out: &mut Vec<u8>) {
                out.$put(*self);
            }
            #[inline]
            fn take(r: &mut Reader<'_>) -> Result<Self, String> {
                r.$take().map_err(String::from)
            }
        }
    )*};
}

wire_int! {
    u8 => put_u8, u8;
    u16 => put_u16, u16;
    u32 => put_u32, u32;
    u64 => put_u64, u64;
    i8 => put_i8, i8;
    i16 => put_i16, i16;
    i32 => put_i32, i32;
    i64 => put_i64, i64;
}

impl Wire for usize {
    fn put(&self, out: &mut Vec<u8>) {
        out.put_u64(*self as u64);
    }
    fn take(r: &mut Reader<'_>) -> Result<Self, String> {
        let it = r.u64().map_err(String::from)?;
        // alloc: error path
        usize::try_from(it).map_err(|_| format!("{it}, past this machine's `usize`"))
    }
}

impl Wire for bool {
    fn put(&self, out: &mut Vec<u8>) {
        out.put_u8(u8::from(*self));
    }
    fn take(r: &mut Reader<'_>) -> Result<Self, String> {
        match r.u8().map_err(String::from)? {
            0 => Ok(false),
            1 => Ok(true),
            // alloc: error path
            other => Err(format!("a bool of {other}")),
        }
    }
}

impl<const N: usize> Wire for [u8; N] {
    fn put(&self, out: &mut Vec<u8>) {
        out.put_bytes(self);
    }
    fn take(r: &mut Reader<'_>) -> Result<Self, String> {
        Ok(*r.array::<N>().map_err(String::from)?)
    }
}

impl Wire for [u32; 2] {
    fn put(&self, out: &mut Vec<u8>) {
        out.put_u32(self[0]);
        out.put_u32(self[1]);
    }
    fn take(r: &mut Reader<'_>) -> Result<Self, String> {
        Ok([u32::take(r)?, u32::take(r)?])
    }
}

impl Wire for [u32; 3] {
    fn put(&self, out: &mut Vec<u8>) {
        for it in self {
            out.put_u32(*it);
        }
    }
    fn take(r: &mut Reader<'_>) -> Result<Self, String> {
        Ok([u32::take(r)?, u32::take(r)?, u32::take(r)?])
    }
}

impl Wire for ContentId {
    fn put(&self, out: &mut Vec<u8>) {
        out.put_bytes(&self.0);
    }
    fn take(r: &mut Reader<'_>) -> Result<Self, String> {
        Ok(ContentId(<[u8; 32]>::take(r)?))
    }
}

impl Wire for InstanceKey {
    fn put(&self, out: &mut Vec<u8>) {
        self.0.put(out);
    }
    fn take(r: &mut Reader<'_>) -> Result<Self, String> {
        Ok(InstanceKey(ContentId::take(r)?))
    }
}

impl Wire for ItemKey {
    fn put(&self, out: &mut Vec<u8>) {
        self.0.put(out);
    }
    fn take(r: &mut Reader<'_>) -> Result<Self, String> {
        Ok(ItemKey(ContentId::take(r)?))
    }
}

impl Wire for String {
    fn put(&self, out: &mut Vec<u8>) {
        out.put_bytes_u64(self.as_bytes());
    }
    fn take(r: &mut Reader<'_>) -> Result<Self, String> {
        // alloc: one string a field, once per restore
        Ok(r.str_u64().map_err(String::from)?.to_owned())
    }
}

impl Wire for Arc<str> {
    fn put(&self, out: &mut Vec<u8>) {
        out.put_bytes_u64(self.as_bytes());
    }
    fn take(r: &mut Reader<'_>) -> Result<Self, String> {
        // alloc: one string a field, once per restore
        Ok(Arc::from(r.str_u64().map_err(String::from)?))
    }
}

/// The `&'static str`s restores have made, each made once a process: a class or section name a
/// writer names with a literal ([`crate::model::Class::Synthetic`]), which compares by its text.
static STATICS: Lock<Vec<&'static str>> = Lock::new("link.checkpoint.statics", Vec::new());

impl Wire for &'static str {
    fn put(&self, out: &mut Vec<u8>) {
        out.put_bytes_u64(self.as_bytes());
    }
    fn take(r: &mut Reader<'_>) -> Result<Self, String> {
        let text = r.str_u64().map_err(String::from)?;
        let mut statics = STATICS.lock();
        if let Some(it) = statics.iter().find(|it| **it == text) {
            return Ok(it);
        }
        // alloc: once a process per distinct name: a writer's few dozen literals, which the
        // restored classes compare by text exactly as the literals they stand for
        let made: &'static str = Box::leak(text.to_owned().into_boxed_str());
        statics.push(made);
        Ok(made)
    }
}

impl<T: Wire> Wire for Option<T> {
    fn put(&self, out: &mut Vec<u8>) {
        match self {
            None => out.put_u8(0),
            Some(it) => {
                out.put_u8(1);
                it.put(out);
            }
        }
    }
    fn take(r: &mut Reader<'_>) -> Result<Self, String> {
        match r.u8().map_err(String::from)? {
            0 => Ok(None),
            1 => Ok(Some(T::take(r)?)),
            // alloc: error path
            other => Err(format!("an option of tag {other}")),
        }
    }
}

impl<T: Wire> Wire for Vec<T> {
    fn put(&self, out: &mut Vec<u8>) {
        put_len(out, self.len());
        for it in self {
            it.put(out);
        }
    }
    fn take(r: &mut Reader<'_>) -> Result<Self, String> {
        let len = count(r, 1)?;
        // alloc: one column, once per restore
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(T::take(r)?);
        }
        Ok(out)
    }
}

impl<T: Wire> Wire for Arc<T> {
    fn put(&self, out: &mut Vec<u8>) {
        (**self).put(out);
    }
    fn take(r: &mut Reader<'_>) -> Result<Self, String> {
        // alloc: one shared value, once per restore
        Ok(Arc::new(T::take(r)?))
    }
}

impl<T: Wire> Wire for Arc<[T]> {
    fn put(&self, out: &mut Vec<u8>) {
        put_len(out, self.len());
        for it in self.iter() {
            it.put(out);
        }
    }
    fn take(r: &mut Reader<'_>) -> Result<Self, String> {
        Ok(Vec::<T>::take(r)?.into())
    }
}

impl<K: Wire + Ord, V: Wire> Wire for BTreeMap<K, V> {
    fn put(&self, out: &mut Vec<u8>) {
        put_len(out, self.len());
        for (k, v) in self {
            k.put(out);
            v.put(out);
        }
    }
    fn take(r: &mut Reader<'_>) -> Result<Self, String> {
        let len = count(r, 1)?;
        let mut out = BTreeMap::new();
        for _ in 0..len {
            let k = K::take(r)?;
            let v = V::take(r)?;
            if out.insert(k, v).is_some() {
                return Err("a map with one key twice".into());
            }
        }
        Ok(out)
    }
}

impl<A: Wire, B: Wire> Wire for (A, B) {
    fn put(&self, out: &mut Vec<u8>) {
        self.0.put(out);
        self.1.put(out);
    }
    fn take(r: &mut Reader<'_>) -> Result<Self, String> {
        Ok((A::take(r)?, B::take(r)?))
    }
}

impl<A: Wire, B: Wire, C: Wire> Wire for (A, B, C) {
    fn put(&self, out: &mut Vec<u8>) {
        self.0.put(out);
        self.1.put(out);
        self.2.put(out);
    }
    fn take(r: &mut Reader<'_>) -> Result<Self, String> {
        Ok((A::take(r)?, B::take(r)?, C::take(r)?))
    }
}

/// A fixed array of a non-byte type, as its elements in order (the state's columns per shard).
pub(crate) fn put_array<T: Wire, const N: usize>(items: &[T; N], out: &mut Vec<u8>) {
    for it in items {
        it.put(out);
    }
}

pub(crate) fn take_array<T: Wire, const N: usize>(r: &mut Reader<'_>) -> Result<[T; N], String> {
    // alloc: once per restore per sharded column, its shards
    let mut items = Vec::with_capacity(N);
    for _ in 0..N {
        items.push(T::take(r)?);
    }
    items.try_into().map_err(|_| "a sharded column of another shard count".to_owned())
}

impl Wire for SpanRef {
    fn put(&self, out: &mut Vec<u8>) {
        self.anchor.put(out);
        self.index.put(out);
    }
    fn take(r: &mut Reader<'_>) -> Result<Self, String> {
        Ok(SpanRef { anchor: ContentId::take(r)?, index: u32::take(r)? })
    }
}

impl Wire for Line {
    fn put(&self, out: &mut Vec<u8>) {
        let Line { at, span } = self;
        at.put(out);
        span.put(out);
    }
    fn take(r: &mut Reader<'_>) -> Result<Self, String> {
        Ok(Line { at: u32::take(r)?, span: SpanRef::take(r)? })
    }
}

mod wire_debug {
    use blaze_codegen::debug::{
        Aggregate, BaseEncoding, DebugType, EnumTag, EnumVariant, Field, FunctionDebug,
        InlinedSite, Local, LocalPlace, Scope,
    };

    wire_enum!(BaseEncoding {
        0 => Bool,
        1 => Char,
        2 => Signed,
        3 => Unsigned,
        4 => Float,
    });
    wire_struct!(Field { name, offset, ty });
    wire_struct!(Aggregate { name, size, fields });
    wire_struct!(EnumTag { offset, size, states });
    wire_struct!(EnumVariant { name, tag, fields });
    wire_enum!(DebugType {
        0 => Base { name, size, encoding },
        1 => Pointer { name, to },
        2 => Array { of, len },
        3 => Struct(it),
        4 => Union(it),
        5 => Names { name, size, names },
        6 => Enum { of, tag, variants },
    });
    wire_struct!(Scope { parent, ranges });
    wire_enum!(LocalPlace {
        0 => Frame(offset),
        1 => Ranges(ranges),
    });
    wire_struct!(Local { name, param, ty, place, scope });
    wire_struct!(InlinedSite { parent, callee, call_site, decl, ranges });
    wire_struct!(FunctionDebug { frame_base, types, scopes, locals, inlined });
}

impl Wire for blaze_codegen::Backend {
    fn put(&self, out: &mut Vec<u8>) {
        use blaze_codegen::Backend;
        match self {
            Backend::Cranelift { speed } => {
                out.put_u8(0);
                speed.put(out);
            }
            Backend::Llvm { opt } => {
                out.put_u8(1);
                opt.put(out);
            }
            Backend::Stencil => out.put_u8(2),
        }
    }
    fn take(r: &mut Reader<'_>) -> Result<Self, String> {
        use blaze_codegen::Backend;
        Ok(match u8::take(r)? {
            0 => Backend::Cranelift { speed: bool::take(r)? },
            1 => Backend::Llvm { opt: u8::take(r)? },
            2 => Backend::Stencil,
            // alloc: error path
            other => return Err(format!("a backend of tag {other}")),
        })
    }
}

impl Wire for Origin {
    fn put(&self, out: &mut Vec<u8>) {
        let (tag, package) = match self {
            Origin::Member(it) => (0, Some(it)),
            Origin::Dependency(it) => (1, Some(it)),
            Origin::BuildTime(it) => (2, Some(it)),
            Origin::Std => (3, None),
        };
        out.put_u8(tag);
        if let Some(package) = package {
            out.put_bytes_u64(package.as_str().as_bytes());
        }
    }
    fn take(r: &mut Reader<'_>) -> Result<Self, String> {
        use blaze_codegen::plan::Package;
        let tag = u8::take(r)?;
        let mut package = || -> Result<Package, String> {
            Ok(Package::new(r.str_u64().map_err(String::from)?))
        };
        Ok(match tag {
            0 => Origin::Member(package()?),
            1 => Origin::Dependency(package()?),
            2 => Origin::BuildTime(package()?),
            3 => Origin::Std,
            // alloc: error path
            other => return Err(format!("an origin of tag {other}")),
        })
    }
}

impl Wire for Made {
    fn put(&self, out: &mut Vec<u8>) {
        let Made { backend, origin } = self;
        backend.put(out);
        origin.put(out);
    }
    fn take(r: &mut Reader<'_>) -> Result<Self, String> {
        Ok(Made { backend: Wire::take(r)?, origin: Wire::take(r)? })
    }
}

/// Why an image has no checkpoint, or a record does not restore: what a caller says when it
/// links from scratch instead.
fn refused(to: &blaze_core::FileName, what: impl std::fmt::Display) -> LinkError {
    // alloc: error path
    LinkError { function: None, what: format!("{to}: {what}"), refusal: None }
}

/// The bytes of a native input a restore hands back, by its content id and the name the link
/// line gave it: the caller's, read as a link reads it.
pub type NativeBytes<'a> = dyn FnMut(ContentId, &str) -> Result<Arc<[u8]>, String> + 'a;

impl Image {
    /// The image as its last commit left it, as one record for [`Image::restore`]: an error
    /// naming why when there is none to make (before the first commit, with a commit in
    /// flight) or when the image keeps what no record holds (a dev run's code memory, a live
    /// image, a lazy one, one linked beside another, a wasm module, which is written whole).
    pub fn checkpoint(&mut self) -> Result<Vec<u8>, LinkError> {
        let to = &self.to;
        if !self.state.laid_out || self.pending.is_some() {
            return Err(refused(to, "no commit to checkpoint: the image is not laid out, or a commit is in flight"));
        }
        if self.output.dev_run.is_some() || self.output.live.is_some() || self.lazy.is_some() {
            return Err(refused(to, "a dev run's or live image's code memory, which no checkpoint holds"));
        }
        if self.place.is_some() {
            return Err(refused(to, "an image fixed beside another, whose place is the run's"));
        }
        if self.output.format == Format::Wasm || !self.output.incremental {
            return Err(refused(to, "an image that keeps no room, which every link lays out whole"));
        }
        let digest = self.digest()?;
        let to = &self.to;
        // alloc: the record, once per checkpoint, the caller's to store
        let mut out = Vec::with_capacity(self.state.file_len as usize / 2 + 4096);
        out.put_bytes(MAGIC);
        out.put_bytes(&digest);
        self.state.generation.put(&mut out);
        self.generations.put(&mut out);
        self.tags.put(&mut out);
        self.symbols.put(&mut out);
        self.state.put_checkpoint(&self.symbols, &mut out).map_err(|what| refused(to, what))?;
        Ok(out)
    }

    /// The image `checkpoint` recorded, at `to` and linked as `output`, its native inputs'
    /// bytes from `natives`: as it was after the commit the checkpoint was made of, so the next
    /// link patches its file. An error naming why when the record is of another layout or
    /// torn, when a native input is not to be had, or when the state it makes is not the one
    /// checkpointed (its file's digest differs). Nothing is kept of a refused restore; the
    /// caller links from scratch.
    pub fn restore(
        to: blaze_core::FileName,
        output: Output,
        checkpoint: &[u8],
        natives: &mut NativeBytes<'_>,
    ) -> Result<Image, LinkError> {
        if output.dev_run.is_some() || output.live.is_some() || output.format == Format::Wasm {
            return Err(refused(&to, "a dev run's, live or wasm image, which no checkpoint holds"));
        }
        let mut image = Image::new(to, output)?;
        let to = image.to.clone();
        let mut r = Reader::new(checkpoint);
        let fail = |what: String| refused(&to, format_args!("its checkpoint does not restore: {what}"));
        if r.array::<8>().ok() != Some(MAGIC) {
            return Err(fail("not a checkpoint of this layout (BLKIMG02): link it from scratch".into()));
        }
        let digest = *r.array::<32>().map_err(|it| fail(it.into()))?;
        let generation = u64::take(&mut r).map_err(&fail)?;
        image.generations = u64::take(&mut r).map_err(&fail)?;
        image.tags = u32::take(&mut r).map_err(&fail)?;
        image.symbols = crate::symbols::Symbols::take(&mut r).map_err(&fail)?;
        let mut objects = std::mem::take(&mut image.objects);
        let state = crate::state::State::take_checkpoint(
            &mut r,
            &image.writer,
            &mut image.symbols,
            &mut objects,
            natives,
        )
        .map_err(&fail)?;
        r.finish().map_err(|it| fail(it.into()))?;
        if state.generation != generation || generation > image.generations {
            return Err(fail(format!(
                "its state is of generation {} and its header says {generation} of {}",
                state.generation, image.generations
            )));
        }
        image.objects = objects;
        image.state = state;
        image.beside = crate::beside::Kept::new();
        image.filed = crate::patch::Filed::new();
        let made = image.digest()?;
        if made != digest {
            return Err(refused(
                &to,
                format_args!(
                    "its checkpoint restores to a file of another digest than the one it recorded (generation {}): link \
                     it from scratch",
                    image.state.generation
                ),
            ));
        }
        if image.output.debug == Debug::Beside {
            // The side file is laid out whole by the next update: its records are of this
            // process's, made again from the restored state ([`Image::debug_file_whole`]).
            image.beside.forget();
        }
        Ok(image)
    }
}
