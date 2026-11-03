//! Demand-loaded GeoIP. Readers retain the old inode across database updates.
//! All application writers stage, validate and atomically rename new files.
//! Manual database updates must also replace files, never edit them in place.
use std::path::Path;
pub type Reader = maxminddb::Reader<maxminddb::Mmap>;
pub fn open(path: impl AsRef<Path>) -> Result<Reader, maxminddb::MaxMindDbError> {
    // SAFETY: The application never writes/truncates an installed database.
    // enrichment::download_geo publishes new inodes with atomic rename.
    // The managed GeoIP directory is not a location for in-place file edits.
    unsafe { Reader::open_mmap(path) }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replacement_keeps_existing_reader_valid_and_reloads_new_records() {
        let dir = std::env::temp_dir().join(format!("genyra-geodb-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("city.mmdb");
        let original = include_bytes!("../tests/fixtures/maxmind/GeoIP2-City-Test.mmdb");
        std::fs::write(&path, original).unwrap();
        let old = open(&path).unwrap();
        let lookup = |reader: &Reader| {
            reader
                .lookup("81.2.69.160".parse().unwrap())
                .unwrap()
                .decode::<serde_json::Value>()
                .unwrap()
                .unwrap()["city"]["names"]["en"]
                .clone()
        };
        assert_eq!(lookup(&old), "London");
        let mut replacement = original.to_vec();
        let offsets: Vec<_> = replacement
            .windows(6)
            .enumerate()
            .filter_map(|(i, v)| (v == b"London").then_some(i))
            .collect();
        assert!(!offsets.is_empty());
        for offset in offsets {
            replacement[offset..offset + 6].copy_from_slice(b"Londox");
        }
        let staged = dir.join("staged.mmdb");
        std::fs::write(&staged, replacement).unwrap();
        std::fs::rename(&staged, &path).unwrap();
        let new = open(&path).unwrap();
        assert_eq!(lookup(&old), "London");
        assert_eq!(lookup(&new), "Londox");
        drop(old);
        drop(new);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
