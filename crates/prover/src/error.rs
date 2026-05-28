//! Errors surfaced by [`load_release`](crate::load_release).

use std::io;

use thiserror::Error;

/// Failure modes of [`load_release`](crate::load_release).
///
/// Categories:
///   * `IntegrityFailure` — staged artifact's streaming SHA256 disagreed
///     with the value in the per-shape `<shape>-SHA256SUMS` or in the
///     per-shape `manifest.json`'s `artifacts.<key>.sha256`.
///   * `MissingArtifact` — an expected file (release-dir source or
///     per-shape sums file) was absent.
///   * `MalformedManifest` — `<shape>-manifest.json` (or sums file) could
///     not be parsed, or did not have the expected shape.
///   * `UnknownShape` — caller passed a shape other than `1-of-1` /
///     `3-of-3`.
///   * `LockFailure` — `fs2::FileExt::lock_exclusive` on the sibling
///     lockfile failed.
///   * `IoError` — generic filesystem error (open / read / write /
///     rename) bubbled up unchanged.
#[derive(Debug, Error)]
pub enum ReleaseError {
    /// Streaming SHA256 of a staged artifact did not match the expected
    /// value from `<shape>-SHA256SUMS` or `manifest.artifacts.<key>.sha256`.
    #[error("release artifact {artifact}: expected {expected}, got {actual}")]
    IntegrityFailure {
        /// Unprefixed artifact filename inside the staged dir (e.g. `pk.bin`).
        artifact: String,
        /// Hex SHA256 declared by the per-shape sums file / manifest.
        expected: String,
        /// Hex SHA256 actually streamed off disk.
        actual: String,
    },

    /// An expected source file or sums entry was missing from the
    /// release directory.
    #[error("release artifact missing: {0}")]
    MissingArtifact(String),

    /// `<shape>-manifest.json` (or `<shape>-SHA256SUMS`) could not be
    /// parsed, or did not contain the keys [`load_release`](crate::load_release)
    /// requires.
    #[error("release manifest malformed: {0}")]
    MalformedManifest(String),

    /// Shape was not one of the supported values (`1-of-1`, `3-of-3`).
    #[error("unknown release shape: {0}")]
    UnknownShape(String),

    /// `fs2::FileExt::lock_exclusive` on the staged-dir sibling lockfile
    /// failed.
    #[error("release-lock failure: {0}")]
    LockFailure(String),

    /// Generic IO error during stage / verify.
    #[error("release IO error: {0}")]
    IoError(#[from] io::Error),
}
