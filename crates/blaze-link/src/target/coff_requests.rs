//! One COFF input's `/DEFAULTLIB` requests, not its resolved paths. A verified CAS read
//! checks the bytes the writer put; the decoder checks the layout and the key they belong to.

use blaze_cas::{Handle, Key, Kind};
use blaze_format::{
    Part, SchemaHash,
    cursor::{Put as _, Reader},
};
use blaze_ids::ContentId;

const MAGIC: &[u8; 4] = b"BCD1";
const SCHEMA: SchemaHash = blaze_format::schema_of(&[Part::Str(
    "COFF /DEFAULTLIB BCD1: key, count:u64, (member:utf8/u64, library:utf8/u64)*",
)]);

pub(super) struct Records<'a> {
    pub(super) store: &'a Handle,
    pub(super) producer: ContentId,
}

impl Records<'_> {
    pub(super) fn requests(
        &self,
        name: &str,
        input: ContentId,
        parse: impl FnOnce() -> Result<Vec<(String, String)>, String>,
    ) -> Result<Vec<(String, String)>, String> {
        let key = Key::of(SCHEMA, self.producer, &[input]);
        let failed = |why| format!("{name}: COFF /DEFAULTLIB record {:x}: {why}", key.0);
        if let Some(found) = self
            .store
            .read(&key, |entry| {
                if entry.kind != Kind::Query {
                    return Err(format!("expected a Query, found {:?}", entry.kind));
                }
                decode(key, entry.bytes)
            })
            .map_err(|err| failed(err.to_string()))?
        {
            return found.map_err(failed);
        }
        let pairs = parse()?;
        self.store.put(key, Kind::Query, &encode(key, &pairs)).map_err(|err| {
            failed(format!(
                "different contents for one key: kept {:x}, made {:x}",
                err.kept, err.given
            ))
        })?;
        Ok(pairs)
    }
}

fn encode(key: Key, pairs: &[(String, String)]) -> Vec<u8> {
    let mut bytes = Vec::new(); // alloc: one store value, only on a miss
    bytes.put_bytes(MAGIC);
    bytes.put_bytes(&key.0.0);
    bytes.put_u64(pairs.len() as u64);
    for (member, library) in pairs {
        bytes.put_bytes_u64(member.as_bytes());
        bytes.put_bytes_u64(library.as_bytes());
    }
    bytes
}

fn decode(key: Key, bytes: &[u8]) -> Result<Vec<(String, String)>, String> {
    let mut r = Reader::new(bytes);
    if r.array::<4>().ok() != Some(MAGIC) {
        return Err("not layout BCD1; rebuild the native-input cache with this blaze".into());
    }
    let error = |err: blaze_format::cursor::Error| err.to_string();
    if r.array::<32>().map_err(error)? != &key.0.0 {
        return Err("record belongs to a different producer or native input".into());
    }
    // No allocation based on an unchecked count. The strings join the existing process cache.
    let count = r.count_u64(16).map_err(error)?;
    let mut pairs = Vec::new(); // alloc: one entry per declared library
    for _ in 0..count {
        let member = r.str_u64().map_err(error)?;
        let library = r.str_u64().map_err(error)?;
        pairs.push((member.to_owned(), library.to_owned()));
    }
    r.finish().map_err(error)?;
    Ok(pairs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coff_restore_rejects_old_layout_wrong_input_and_malformed_rows() {
        let key = Key(ContentId([1; 32]));
        // Previously the unit stored a BZU2 header: counts, output keys, native hashes
        // and paths, no requests. Even a valid empty header isn't an empty request list.
        let old = b"BZU2\0\0\0\0\0\0\0\0\0\0\0\0";
        assert!(decode(key, old).unwrap_err().contains("not layout BCD1"));
        let rows = vec![(String::new(), "one.lib".into()), ("a.obj".into(), "two.lib".into())];
        let bytes = encode(key, &rows);
        assert_eq!(decode(key, &bytes).unwrap(), rows);
        assert!(
            decode(Key(ContentId([2; 32])), &bytes)
                .unwrap_err()
                .contains("different producer or native input")
        );
        for end in 0..bytes.len() {
            assert!(decode(key, &bytes[..end]).is_err(), "accepted prefix {end}");
        }
        let mut bad = bytes.clone();
        *bad.last_mut().unwrap() = 0xff;
        assert!(decode(key, &bad).is_err());
        bad = bytes;
        bad.push(0);
        assert!(decode(key, &bad).is_err());
    }
}
