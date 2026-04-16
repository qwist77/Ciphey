//! Path validation helpers for user-provided filesystem access.

use std::env;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io;
use std::path::{Component, Path, PathBuf};

/// The default filename used when exporting plaintext to disk.
pub const DEFAULT_EXPORT_FILENAME: &str = "ciphey_text.txt";

/// Resolves a user-provided export filename to a path under the current user's home directory.
///
/// Only bare filenames are accepted. Directory separators, traversal segments, and absolute paths
/// are rejected so interactive exports cannot write outside the user's home directory.
pub fn resolve_output_path(file_name_input: &str) -> io::Result<PathBuf> {
    let file_name = match file_name_input.trim() {
        "" => DEFAULT_EXPORT_FILENAME,
        value => value,
    };

    if !is_plain_filename(file_name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Please enter a filename without any path separators",
        ));
    }

    Ok(home_directory()?.join(file_name))
}

/// Validates a first-run wordlist path and returns its canonical location.
///
/// Wordlists must resolve to a readable regular file inside one of the trusted roots returned by
/// [`allowed_wordlist_roots`].
pub fn validate_wordlist_path(input: &str) -> io::Result<PathBuf> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Wordlist path cannot be empty",
        ));
    }

    let canonical_path = fs::canonicalize(trimmed)
        .map_err(|error| io::Error::new(error.kind(), format!("Cannot access file: {error}")))?;
    let metadata = fs::metadata(&canonical_path)?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Wordlist path must point to a regular file",
        ));
    }

    let allowed_roots = allowed_wordlist_roots()?;
    if !allowed_roots
        .iter()
        .any(|root| canonical_path.starts_with(root))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Wordlist files must be inside the current directory, home directory, or a system wordlist directory",
        ));
    }

    File::open(&canonical_path)
        .map_err(|error| io::Error::new(error.kind(), format!("Cannot read file: {error}")))?;
    Ok(canonical_path)
}

/// Returns the current user's home directory.
fn home_directory() -> io::Result<PathBuf> {
    if let Some(home) = env::var_os("HOME").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(home));
    }

    if let Some(home) = env::var_os("USERPROFILE").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(home));
    }

    match (env::var_os("HOMEDRIVE"), env::var_os("HOMEPATH")) {
        (Some(drive), Some(path)) if !drive.is_empty() && !path.is_empty() => {
            let mut home = PathBuf::from(drive);
            home.push(path);
            Ok(home)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Could not determine the current user's home directory",
        )),
    }
}

/// Returns the canonical filesystem roots accepted for first-run wordlist selection.
fn allowed_wordlist_roots() -> io::Result<Vec<PathBuf>> {
    let mut roots = Vec::new();

    push_canonical_root(&mut roots, env::current_dir()?);
    push_canonical_root(&mut roots, home_directory()?);

    #[cfg(not(windows))]
    {
        push_optional_root(&mut roots, Path::new("/usr/share"));
        push_optional_root(&mut roots, Path::new("/usr/local/share"));
        push_optional_root(&mut roots, Path::new("/opt/homebrew/share"));
    }

    Ok(roots)
}

/// Adds a canonicalized root path to the allowlist when it exists.
fn push_canonical_root(roots: &mut Vec<PathBuf>, candidate: PathBuf) {
    if let Ok(canonical_root) = fs::canonicalize(candidate) {
        if !roots.iter().any(|root| root == &canonical_root) {
            roots.push(canonical_root);
        }
    }
}

/// Attempts to add an optional root path to the allowlist.
fn push_optional_root(roots: &mut Vec<PathBuf>, candidate: &Path) {
    push_canonical_root(roots, candidate.to_path_buf());
}

/// Returns true when the provided string is a single filename component.
fn is_plain_filename(file_name: &str) -> bool {
    matches!(
        Path::new(file_name).components().next(),
        Some(Component::Normal(component))
            if component == OsStr::new(file_name)
                && Path::new(file_name).components().count() == 1
    )
}

#[cfg(test)]
mod tests {
    use super::{resolve_output_path, validate_wordlist_path, DEFAULT_EXPORT_FILENAME};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Ensures plaintext exports stay within the caller's home directory.
    #[test]
    fn resolve_output_path_uses_home_directory() {
        let resolved = resolve_output_path("").expect("expected default output path");
        assert!(resolved.ends_with(DEFAULT_EXPORT_FILENAME));
        assert!(resolved.is_absolute());
    }

    /// Rejects nested paths so callers cannot escape the export directory.
    #[test]
    fn resolve_output_path_rejects_nested_paths() {
        assert!(resolve_output_path("../secret.txt").is_err());
        assert!(resolve_output_path("nested/output.txt").is_err());
    }

    /// Accepts readable wordlists stored beneath the current working directory.
    #[test]
    fn validate_wordlist_path_accepts_repo_local_file() {
        let unique_suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after unix epoch")
            .as_nanos();
        let test_dir = std::env::current_dir()
            .expect("expected current dir")
            .join("target")
            .join("path-security-tests");
        fs::create_dir_all(&test_dir).expect("expected test directory to be created");

        let wordlist_path = test_dir.join(format!("wordlist-{unique_suffix}.txt"));
        fs::write(&wordlist_path, "hello\nworld\n").expect("expected wordlist to be written");

        let validated =
            validate_wordlist_path(wordlist_path.to_str().expect("expected utf-8 path"))
                .expect("expected wordlist path to validate");
        assert_eq!(
            validated,
            fs::canonicalize(&wordlist_path).expect("expected canonical wordlist path")
        );

        fs::remove_file(&wordlist_path).expect("expected wordlist to be removed");
    }
}
