//! Error type for ad-hoc signing and verification.

/// Errors that can occur during ad-hoc signing or signature verification.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SignError {
    /// An I/O error occurred while reading or writing.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// The input does not start with a Mach-O (or fat/universal) magic number.
    #[error("not a Mach-O binary")]
    NotMachO,

    /// The Mach-O binary could not be parsed.
    #[error("malformed Mach-O binary: {0}")]
    Malformed(String),

    /// Fat (universal) binaries cannot be signed in a single streaming pass
    /// because the size of each signed slice must be known up front. Use
    /// [`crate::adhoc_sign`] or [`crate::adhoc_sign_file`] which handle fat
    /// binaries by signing each architecture slice in memory.
    #[error(
        "fat (universal) Mach-O binaries cannot be signed in a single streaming pass; \
         use `adhoc_sign` or `adhoc_sign_file` instead"
    )]
    FatBinaryNotStreamable,

    /// Fat binaries with 64-bit fat headers (`FAT_MAGIC_64`) are exceedingly
    /// rare and not supported.
    #[error("fat (universal) Mach-O binaries with 64-bit fat headers are not supported")]
    Fat64Unsupported,

    /// [`crate::Entitlements::Preserve`] requires random access to the
    /// existing signature which a streaming signer does not have. Extract the
    /// entitlements up front with [`crate::extract_entitlements`] and pass
    /// them as [`crate::Entitlements::Custom`].
    #[error(
        "`Entitlements::Preserve` is not supported by the streaming signer; extract the \
         entitlements up front with `extract_entitlements` and pass `Entitlements::Custom`"
    )]
    CannotPreserveWhenStreaming,

    /// The binary has no `__LINKEDIT` segment, which is required to hold the
    /// code signature.
    #[error("binary has no __LINKEDIT segment")]
    MissingLinkedit,

    /// The binary has no `LC_CODE_SIGNATURE` load command and there is not
    /// enough zero padding after the load commands to insert one.
    #[error(
        "not enough header padding to insert an LC_CODE_SIGNATURE load command; \
         relink the binary with `-Wl,-headerpad,0x100`"
    )]
    InsufficientHeaderPadding,

    /// The input ended before all code pages could be hashed.
    #[error("input ended prematurely: expected at least {expected} bytes, got {got}")]
    TruncatedInput {
        /// The minimum number of bytes that were expected.
        expected: u64,
        /// The number of bytes that were actually provided.
        got: u64,
    },

    /// An offset or size does not fit in the fields of the Mach-O structures
    /// (code signatures must start within the first 4 GiB of the file).
    #[error("binary too large to sign: {0}")]
    TooLarge(String),

    /// Signature verification failed.
    #[error("signature verification failed: {0}")]
    VerificationFailed(String),
}

impl SignError {
    /// Convert into an [`std::io::Error`], unwrapping I/O errors.
    pub fn into_io_error(self) -> std::io::Error {
        match self {
            SignError::Io(err) => err,
            other => std::io::Error::new(std::io::ErrorKind::InvalidData, other),
        }
    }
}
