//! Fast ad-hoc code signing for Mach-O binaries.
//!
//! This crate implements ad-hoc code signing (the equivalent of
//! `codesign --force --sign -`) as a pure-Rust library. It works on any host
//! platform — no Apple tooling required — and is designed for high-throughput
//! use cases such as package installers that need to re-sign thousands of
//! binaries after patching them.
//!
//! # APIs
//!
//! * [`adhoc_sign`] — sign a binary held in memory. Supports thin and fat
//!   (universal) binaries.
//! * [`adhoc_sign_file`] — sign a file in place (atomic replace, permissions
//!   preserved). Thin binaries are processed in a single streaming pass.
//! * [`StreamingSigner`] — a [`std::io::Write`] adapter that signs a thin
//!   binary while it is being written, enabling single-pass
//!   "transform + sign" pipelines: bytes in, signed bytes out, no second
//!   pass over the file.
//! * [`verify`] — re-check all hashes and structural invariants of a signed
//!   binary, on any host platform.
//! * [`extract_entitlements`] / [`is_linker_signed`] / [`macho_kind`] —
//!   helpers for inspecting existing binaries.
//!
//! # Example
//!
//! ```no_run
//! use arwen_codesign::{adhoc_sign_file, AdhocSignOptions, Entitlements};
//!
//! // Equivalent to `codesign --force --sign - --preserve-metadata=entitlements`:
//! let options = AdhocSignOptions::new("libfoo.dylib")
//!     .with_entitlements(Entitlements::Preserve);
//! adhoc_sign_file(std::path::Path::new("libfoo.dylib"), &options)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # Cargo features
//!
//! * `parallel` — hash code pages in parallel with rayon (used by the
//!   in-memory [`adhoc_sign`] path). Recommended when signing few, large
//!   binaries; unnecessary when the caller already parallelizes across
//!   files.
//! * `asm` — use assembly implementations of SHA-256 (requires a C
//!   toolchain).
//!
//! # Compatibility notes
//!
//! The produced signatures match what Apple's `codesign --sign -` generates
//! for flat (non-bundle) files: a version `0x20400` CodeDirectory with
//! SHA-256 page hashes, an empty Requirements blob and an empty CMS
//! signature wrapper. Known limitations:
//!
//! * Entitlements are embedded in plist form only (special slot 5); the
//!   DER-encoded entitlements slot (slot 7) that `codesign` additionally
//!   emits on macOS 12+ is not generated. This does not affect binaries
//!   without entitlements — the common case for ad-hoc signing.
//! * Hardened runtime signing emits a version `0x20400` CodeDirectory with
//!   the `CS_RUNTIME` flag, without the "runtime version" field of version
//!   `0x20500` directories.

mod blob;
mod error;
mod layout;
mod macho;
mod sign;
mod verify;

pub use blob::{extract_entitlements, is_linker_signed};
pub use error::SignError;
pub use macho::{macho_kind, MachOKind};
pub use sign::{adhoc_sign, adhoc_sign_file, StreamingSigner};
pub use verify::{verify, SignatureInfo};

/// Code signature magic numbers and constants.
pub mod constants {
    /// Magic number for embedded signature SuperBlob
    pub const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade0cc0;
    /// Magic number for CodeDirectory blob
    pub const CSMAGIC_CODEDIRECTORY: u32 = 0xfade0c02;
    /// Magic number for Requirements blob
    pub const CSMAGIC_REQUIREMENTS: u32 = 0xfade0c01;
    /// Magic number for BlobWrapper (used for CMS signature)
    pub const CSMAGIC_BLOBWRAPPER: u32 = 0xfade0b01;
    /// Magic number for embedded entitlements (plist format)
    pub const CSMAGIC_EMBEDDED_ENTITLEMENTS: u32 = 0xfade7171;
    /// Magic number for embedded entitlements (DER format)
    pub const CSMAGIC_EMBEDDED_ENTITLEMENTS_DER: u32 = 0xfade7172;
    /// Slot index for CodeDirectory
    pub const CSSLOT_CODEDIRECTORY: u32 = 0;
    /// Slot index for Info.plist (special slot -1)
    pub const CSSLOT_INFOSLOT: u32 = 1;
    /// Slot index for Requirements (special slot -2)
    pub const CSSLOT_REQUIREMENTS: u32 = 2;
    /// Slot index for entitlements (special slot -5)
    pub const CSSLOT_ENTITLEMENTS: u32 = 5;
    /// Slot index for DER entitlements (special slot -7)
    pub const CSSLOT_ENTITLEMENTS_DER: u32 = 7;
    /// Slot index for CMS Signature
    pub const CSSLOT_SIGNATURESLOT: u32 = 0x10000;
    /// SHA-256 hash type
    pub const CS_HASHTYPE_SHA256: u8 = 2;
    /// Ad-hoc signature flag
    pub const CS_ADHOC: u32 = 0x0002;
    /// Hardened runtime flag (`codesign --options runtime`)
    pub const CS_RUNTIME: u32 = 0x10000;
    /// Linker-signed flag
    pub const CS_LINKER_SIGNED: u32 = 0x20000;
    /// Main binary exec segment flag
    pub const CS_EXECSEG_MAIN_BINARY: u64 = 0x1;
    /// Code signature page size (4 KiB)
    pub const CS_PAGE_SIZE: usize = 4096;
    /// Code signature page size as log2
    pub const CS_PAGE_SIZE_LOG2: u8 = 12;
    /// CodeDirectory version
    pub const CS_VERSION: u32 = 0x20400;
}

/// How to handle entitlements during ad-hoc signing.
#[derive(Debug, Clone, Default)]
pub enum Entitlements<'a> {
    /// No entitlements.
    #[default]
    None,
    /// Preserve existing entitlements from the binary's current signature
    /// (the equivalent of `codesign --preserve-metadata=entitlements`).
    ///
    /// Not supported by [`StreamingSigner`]; extract the entitlements up
    /// front with [`extract_entitlements`] and pass [`Entitlements::Custom`]
    /// instead.
    Preserve,
    /// Use custom entitlements plist data.
    Custom(&'a [u8]),
}

/// Options for ad-hoc code signing.
///
/// # Example
///
/// ```
/// use arwen_codesign::{AdhocSignOptions, Entitlements};
///
/// let options = AdhocSignOptions::new("com.example.myapp")
///     .with_hardened_runtime()
///     .with_entitlements(Entitlements::Preserve);
/// ```
#[derive(Debug, Clone)]
pub struct AdhocSignOptions<'a> {
    /// The identifier to embed in the signature. Apple's `codesign` derives
    /// this from the file name when signing with `-`; passing the file name
    /// is a good default.
    pub identifier: &'a str,
    /// Enable hardened runtime (equivalent to `codesign --options runtime`).
    pub hardened_runtime: bool,
    /// How to handle entitlements.
    pub entitlements: Entitlements<'a>,
    /// Set the linker-signed flag (`CS_LINKER_SIGNED`). Use this when
    /// emulating a linker signature; plain `codesign --sign -` does not set
    /// it, even when re-signing a linker-signed binary.
    pub linker_signed: bool,
}

impl<'a> AdhocSignOptions<'a> {
    /// Create new options with just an identifier (no hardened runtime, no
    /// entitlements).
    pub fn new(identifier: &'a str) -> Self {
        Self {
            identifier,
            hardened_runtime: false,
            entitlements: Entitlements::None,
            linker_signed: false,
        }
    }

    /// Enable hardened runtime.
    pub fn with_hardened_runtime(mut self) -> Self {
        self.hardened_runtime = true;
        self
    }

    /// Set entitlements handling.
    pub fn with_entitlements(mut self, entitlements: Entitlements<'a>) -> Self {
        self.entitlements = entitlements;
        self
    }

    /// Set the linker-signed flag.
    pub fn with_linker_signed(mut self) -> Self {
        self.linker_signed = true;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_builder() {
        let options = AdhocSignOptions::new("com.example.test");
        assert_eq!(options.identifier, "com.example.test");
        assert!(!options.hardened_runtime);
        assert!(!options.linker_signed);

        let options = AdhocSignOptions::new("com.example.test")
            .with_hardened_runtime()
            .with_linker_signed();
        assert!(options.hardened_runtime);
        assert!(options.linker_signed);
    }
}
