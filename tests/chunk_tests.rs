use n0n::chunk;
use std::path::PathBuf;

#[test]
fn test_split_and_assemble() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), b"Hello world! This is a test file to chunk.").unwrap();

    let chunks = chunk::split_file_into_chunks(&PathBuf::from(tmp.path()), 10, "test.txt").unwrap();
    assert!(chunks.len() >= 1);

    let assembled = chunk::assemble_file_from_chunks(&chunks).unwrap();
    assert_eq!(assembled, std::fs::read(tmp.path()).unwrap());
}
