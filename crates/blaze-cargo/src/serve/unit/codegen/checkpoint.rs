//! A kept image across a daemon's stop and start ([`blaze_link::Image::checkpoint`]): at a
//! stop each kept image is written to a file of its own under the daemon's state, and the
//! first link of its path in the next daemon restores it, so that link patches the file the
//! last one left instead of laying the image out from scratch (docs/v2/plan/design/restore.md).
//!
//! A checkpoint is the state of one path's image, not a value of content: each stop writes it
//! again at the same name, which is the hash of the path, the output the image is linked as
//! and the profile it is laid out by, and of the code that wrote it. So it is a file of the
//! daemon's state and never a store record, whose key names one value for good. An older one
//! (a daemon that ended without a stop after linking again) is an older image, which patches
//! as correctly: what a link writes of the file is placed whole where the path does not hold
//! the file the patch is of (`Jobs::place_made`), and the store derives it only from a file it
//! holds (`Written::linked`).
//!
//! With the image go the link's rows of its functions, statics and span tables, its natives
//! and names, which the next build's change is made against ([`super::kept::Rows`]): the rows
//! with no build ([`super::kept::Rows::takes`]), so that change is made from the build's whole
//! lists, against what the image holds.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use blaze_codegen::InstanceKey;
use blaze_format::cursor::{Put as _, Reader};
use blaze_ids::ContentId;
use blaze_items::ItemKey;
use blaze_link::{Image, Output};
use hir_ty_codegen::v2::GlobalAsmObject;

use super::{Job, Linked, kept};

/// The record's first bytes, and the layout they name.
const MAGIC: &[u8; 8] = b"BLKLNK01";
const NAME_DOMAIN: &str = "blaze v2 link checkpoint name 1";

/// Where checkpoints are written and the code identity of the blaze that writes them: set once
/// by the daemon ([`keep`]); without it nothing is written or restored (a test's daemons).
static KEPT: OnceLock<(PathBuf, ContentId)> = OnceLock::new();

/// Checkpoints go under `dir`, named for blaze of code identity `producer`.
pub(crate) fn keep(dir: PathBuf, producer: ContentId) -> Result<(), String> {
    std::fs::create_dir_all(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    KEPT.set((dir, producer)).map_err(|_| "the link checkpoints' directory was already set".to_owned())
}

/// The file the checkpoint of the image at `path`, linked as `output` and laid out by
/// `layout`, is at.
fn file_of(dir: &Path, producer: ContentId, path: &str, output: &Output, layout: Option<ContentId>) -> PathBuf {
    let mut hasher = blaze_ids::Hasher::new(NAME_DOMAIN);
    hasher.id(&producer);
    hasher.update(&(path.len() as u64).to_le_bytes()).update(path.as_bytes());
    // Every field of the output, as its derived `Debug` prints each: an image of another
    // output is laid out anew by its link, as `kept_image` lays one out.
    let output = format!("{output:?}");
    hasher.update(&(output.len() as u64).to_le_bytes()).update(output.as_bytes());
    match layout {
        Some(id) => hasher.update(&[1]).id(&id),
        None => hasher.update(&[0]),
    };
    let name = hasher.finish();
    dir.join(format!("{name:x}.blaze-link"))
}

/// Writes the checkpoint of `linked`, the image kept at `path`: whether one was written. An
/// image no checkpoint holds (a dev run's, a wasm module), or one whose write fails, is said
/// and not written; the next daemon lays it out from scratch.
pub(crate) fn put(linked: &mut Linked, path: &str) -> bool {
    let Some((dir, producer)) = KEPT.get() else { return false };
    if linked.loaded.is_some() || !linked.slotted.is_empty() || !linked.assumed.is_empty() {
        return false;
    }
    let span = tracing::info_span!(target: "blaze", "link checkpoint", unit = %path, bytes = tracing::field::Empty).entered();
    let image = match linked.image.checkpoint() {
        Ok(it) => it,
        Err(why) => {
            tracing::info!(target: "blaze", unit = %path, why = %why, "no link checkpoint");
            return false;
        }
    };
    // alloc: the record, once per kept image per stop
    let mut out = Vec::with_capacity(image.len() + 64 * linked.rows.functions.len() + 4096);
    out.put_bytes(MAGIC);
    put_rows(&linked.rows, &mut out);
    out.put_u64(linked.natives.len() as u64);
    for it in &linked.natives {
        out.put_bytes(&it.0);
    }
    out.put_u64(linked.names.len() as u64);
    for it in &linked.names {
        out.put_bytes_u64(it.as_bytes());
    }
    put_id(linked.layout, &mut out);
    put_id(linked.given, &mut out);
    out.put_bytes_u64(&image);
    span.record("bytes", out.len());
    let file = file_of(dir, *producer, path, &linked.output, linked.layout);
    let next = file.with_extension("blaze-link-next");
    let written = std::fs::write(&next, &out).and_then(|()| std::fs::rename(&next, &file));
    match written {
        Ok(()) => true,
        Err(error) => {
            tracing::warn!(target: "blaze", unit = %path, file = %file.display(), %error, "the link checkpoint was not written");
            false
        }
    }
}

/// The image at `path` the last daemon's stop checkpointed, restored with the natives this
/// link has (`assembled`, `located`): `None` when there is none, or when it does not restore
/// (another layout, a native input this link does not have, a state that does not make the
/// file it recorded), which is said; the link then lays the image out from scratch.
pub(crate) fn restore(
    job: &Job,
    path: &str,
    output: &Output,
    layout: Option<ContentId>,
    assembled: &[GlobalAsmObject],
    located: &[blaze_link::target::Located],
) -> Option<Linked> {
    let (dir, producer) = KEPT.get()?;
    if output.dev_run.is_some() || output.live.is_some() {
        return None;
    }
    let file = file_of(dir, *producer, path, output, layout);
    let bytes = std::fs::read(&file).ok()?;
    let span = tracing::info_span!(target: "blaze", "link restore", unit = %path, bytes = bytes.len()).entered();
    let restored = restore_from(job, path, output, layout, assembled, located, &bytes);
    drop(span);
    match restored {
        Ok(linked) => Some(linked),
        Err(why) => {
            tracing::info!(target: "blaze", unit = %path, why = %why, "the link checkpoint does not restore: the image is laid out from scratch");
            // A checkpoint that does not restore is never tried again.
            let _ = std::fs::remove_file(&file);
            None
        }
    }
}

fn restore_from(
    job: &Job,
    path: &str,
    output: &Output,
    layout: Option<ContentId>,
    assembled: &[GlobalAsmObject],
    located: &[blaze_link::target::Located],
    bytes: &[u8],
) -> Result<Linked, String> {
    let mut r = Reader::new(bytes);
    if r.array::<8>().ok() != Some(MAGIC) {
        return Err("not a link checkpoint of this layout (BLKLNK01)".into());
    }
    let rows = take_rows(&mut r)?;
    let natives = (0..count(&mut r, 32)?)
        .map(|_| Ok(ContentId(*r.array::<32>().map_err(String::from)?)))
        .collect::<Result<Vec<_>, String>>()?;
    let names = (0..count(&mut r, 8)?)
        .map(|_| Ok(r.str_u64().map_err(String::from)?.to_owned()))
        .collect::<Result<Vec<_>, String>>()?;
    let kept_layout = take_id(&mut r)?;
    let given = take_id(&mut r)?;
    let image = r.bytes_u64().map_err(String::from)?;
    r.finish().map_err(String::from)?;
    if kept_layout != layout {
        return Err("a checkpoint laid out by another profile".into());
    }
    // The natives this link has, by content: each file hashed as the link hashes it (the
    // build's looks keep the hash for the link's own), read only when the image asks for it.
    let mut files = blaze_usercode::inputs::Disk::new(Vec::new(), &job.input.looks);
    // alloc: once per restore, the link line's files by content
    let mut line: Vec<(ContentId, Line<'_>)> = Vec::with_capacity(assembled.len() + located.len());
    line.extend(assembled.iter().map(|it| (it.id, Line::Made(&it.bytes))));
    for it in located {
        match &it.made {
            Some((id, bytes)) => line.push((*id, Line::Made(bytes))),
            None => {
                let hash = blaze_usercode::trace::Inputs::file(&mut files, &it.path)
                    .map_err(|it| format!("{}: {}", it.path.display(), it.error))?
                    .ok_or_else(|| format!("{}: no file", it.path.display()))?;
                line.push((ContentId(hash), Line::Read(&it.path)));
            }
        }
    }
    let mut handed = |id: ContentId, name: &str| -> Result<Arc<[u8]>, String> {
        match line.iter().find(|it| it.0 == id) {
            // clone: an `Arc`: the made object, shared with the image
            Some((_, Line::Made(bytes))) => Ok(Arc::clone(bytes)),
            Some((_, Line::Read(at))) => job
                .shared
                .native_bytes
                .get_or_read(id, at)
                .map_err(|it| format!("{}: {}", it.path.display(), it.error)),
            None => Err(format!("{name} is not on this link's line as it was (its content changed, or it went)")),
        }
    };
    let to = blaze_core::FileName::new(path.trim_start_matches('/')).ok_or("a path that names no file")?;
    let image = Image::restore(to, output.clone(), image, &mut handed).map_err(|it| it.to_string())?;
    Ok(Linked {
        image,
        output: output.clone(),
        rows,
        natives,
        names,
        layout,
        loaded: None,
        slotted: Vec::new(),
        assumed: Vec::new(),
        given,
    })
}

/// A file of the link line, for a restore to hand the image its bytes.
enum Line<'a> {
    Made(&'a Arc<[u8]>),
    Read(&'a Path),
}

fn count(r: &mut Reader<'_>, each: usize) -> Result<usize, String> {
    r.count_u64(each).map_err(String::from)
}

fn put_id(id: Option<ContentId>, out: &mut Vec<u8>) {
    match id {
        None => out.put_u8(0),
        Some(id) => {
            out.put_u8(1);
            out.put_bytes(&id.0);
        }
    }
}

fn take_id(r: &mut Reader<'_>) -> Result<Option<ContentId>, String> {
    match r.u8().map_err(String::from)? {
        0 => Ok(None),
        1 => Ok(Some(ContentId(*r.array::<32>().map_err(String::from)?))),
        other => Err(format!("an id of tag {other}")),
    }
}

fn put_rows(rows: &kept::Rows, out: &mut Vec<u8>) {
    out.put_u64(rows.functions.len() as u64);
    for (key, row) in &rows.functions {
        out.put_bytes(&key.0.0);
        out.put_bytes(&row.0);
    }
    out.put_u64(rows.statics.len() as u64);
    for ((item, instance), row) in &rows.statics {
        out.put_bytes(&item.0.0);
        out.put_bytes(&instance.0);
        out.put_bytes(&row.0);
    }
    out.put_u64(rows.spans.len() as u64);
    for (anchor, id) in &rows.spans {
        out.put_bytes(&anchor.0);
        out.put_bytes(&id.0);
    }
}

fn take_rows(r: &mut Reader<'_>) -> Result<kept::Rows, String> {
    let mut id = |r: &mut Reader<'_>| -> Result<ContentId, String> {
        Ok(ContentId(*r.array::<32>().map_err(String::from)?))
    };
    let mut functions = std::collections::BTreeMap::new();
    for _ in 0..count(r, 64)? {
        let key = InstanceKey(id(r)?);
        functions.insert(key, id(r)?);
    }
    let mut statics = std::collections::BTreeMap::new();
    for _ in 0..count(r, 96)? {
        let item = ItemKey(id(r)?);
        let instance = id(r)?;
        statics.insert((item, instance), id(r)?);
    }
    let mut spans = std::collections::BTreeMap::new();
    for _ in 0..count(r, 64)? {
        let anchor = id(r)?;
        spans.insert(anchor, id(r)?);
    }
    Ok(kept::Rows::restored(functions, statics, spans))
}
