use anyhow::Result;
use std::path::Path;

#[allow(dead_code)]
pub fn search_by_hash_local(base: &Path, hash: &str) -> Result<Vec<std::path::PathBuf>> {
    let mut results = Vec::new();
    if base.exists() {
        for entry in walkdir::WalkDir::new(base).into_iter().filter_map(|e| e.ok()) {
            if entry.file_name() == hash {
                results.push(entry.path().to_path_buf());
            }
        }
    }
    Ok(results)
}
