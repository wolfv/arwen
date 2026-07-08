//! Verification of embedded ad-hoc code signatures.
//!
//! [`verify`] re-parses a signed binary, recomputes every code page hash and
//! the special slot hashes, and checks all structural invariants the kernel
//! relies on. It is primarily meant for tests and tooling that want to check
//! a signature without a macOS machine, but it is also useful as a
//! post-signing sanity check in production pipelines.

use sha2::{Digest, Sha256};

use crate::blob;
use crate::constants::*;
use crate::error::SignError;
use crate::layout::HASH_SIZE;
use crate::macho::{self, MachOKind};

/// Information about a verified code signature.
#[derive(Debug, Clone)]
pub struct SignatureInfo {
    /// The signature identifier.
    pub identifier: String,
    /// CodeDirectory flags (`CS_ADHOC`, `CS_RUNTIME`, `CS_LINKER_SIGNED`, ...).
    pub flags: u32,
    /// The number of bytes covered by the code page hashes.
    pub code_limit: u64,
    /// The number of hashed code pages.
    pub n_code_slots: u32,
    /// The number of special (negative index) hash slots.
    pub n_special_slots: u32,
    /// The SHA-256 hash of the CodeDirectory blob (the "cdhash").
    pub cd_hash: [u8; HASH_SIZE],
    /// Whether the signature embeds entitlements.
    pub has_entitlements: bool,
}

fn fail(message: impl Into<String>) -> SignError {
    SignError::VerificationFailed(message.into())
}

/// Verify the embedded code signature(s) of a Mach-O binary.
///
/// For thin binaries the returned vector contains a single entry; for fat
/// (universal) binaries it contains one entry per architecture slice.
///
/// This checks that:
/// * the signature is located at the end of `__LINKEDIT`, which ends exactly
///   at the end of the file;
/// * the CodeDirectory covers the whole file up to the signature;
/// * every SHA-256 code page hash matches the file contents;
/// * the special slot hashes match the Requirements/Entitlements blobs.
pub fn verify(data: &[u8]) -> Result<Vec<SignatureInfo>, SignError> {
    match macho::macho_kind(data) {
        None => Err(SignError::NotMachO),
        Some(MachOKind::Fat64) => Err(SignError::Fat64Unsupported),
        Some(MachOKind::Fat) => {
            let n_arches = macho::read_u32(data, 4, false, "fat arch count")? as usize;
            let mut infos = Vec::with_capacity(n_arches);
            for i in 0..n_arches {
                let base = 8 + i * 20;
                let offset = macho::read_u32(data, base + 8, false, "fat slice offset")? as usize;
                let size = macho::read_u32(data, base + 12, false, "fat slice size")? as usize;
                let slice = data
                    .get(
                        offset
                            ..offset
                                .checked_add(size)
                                .ok_or_else(|| fail("fat slice overflow"))?,
                    )
                    .ok_or_else(|| {
                        fail(format!("fat slice {i} extends past the end of the file"))
                    })?;
                infos
                    .push(verify_thin(slice).map_err(|err| fail(format!("fat slice {i}: {err}")))?);
            }
            Ok(infos)
        }
        Some(_) => Ok(vec![verify_thin(data)?]),
    }
}

fn verify_thin(data: &[u8]) -> Result<SignatureInfo, SignError> {
    let info = macho::parse_load_info(data)?;
    let codesig = info
        .codesig
        .ok_or_else(|| fail("binary has no LC_CODE_SIGNATURE load command"))?;
    let linkedit = info.linkedit.ok_or(SignError::MissingLinkedit)?;

    let sig_start = u64::from(codesig.data_offset);
    let sig_end = sig_start + u64::from(codesig.data_size);
    if sig_end != data.len() as u64 {
        return Err(fail(format!(
            "signature region ends at {sig_end} but the file is {} bytes",
            data.len()
        )));
    }
    if linkedit.fileoff + linkedit.filesize != data.len() as u64 {
        return Err(fail(
            "__LINKEDIT segment does not end at the end of the file",
        ));
    }
    let sig = &data[sig_start as usize..];

    let superblob_len = macho::read_u32(sig, 4, false, "SuperBlob length")?;
    if u64::from(superblob_len) > u64::from(codesig.data_size) {
        return Err(fail(
            "SuperBlob length exceeds the allocated signature region",
        ));
    }

    let (cd_magic, cd) = blob::find_blob(sig, CSSLOT_CODEDIRECTORY)
        .ok_or_else(|| fail("signature has no CodeDirectory blob"))?;
    if cd_magic != CSMAGIC_CODEDIRECTORY {
        return Err(fail("CodeDirectory blob has the wrong magic"));
    }

    let cd_u32 = |offset: usize, what: &str| -> Result<u32, SignError> {
        macho::read_u32(cd, offset, false, what)
    };
    let version = cd_u32(8, "CodeDirectory version")?;
    if version < 0x20100 {
        return Err(fail(format!(
            "unsupported CodeDirectory version {version:#x}"
        )));
    }
    let flags = cd_u32(12, "flags")?;
    let hash_offset = cd_u32(16, "hashOffset")? as usize;
    let ident_offset = cd_u32(20, "identOffset")? as usize;
    let n_special_slots = cd_u32(24, "nSpecialSlots")?;
    let n_code_slots = cd_u32(28, "nCodeSlots")?;
    let code_limit = u64::from(cd_u32(32, "codeLimit")?);
    let hash_size = *cd.get(36).ok_or_else(|| fail("CodeDirectory too small"))?;
    let hash_type = *cd.get(37).ok_or_else(|| fail("CodeDirectory too small"))?;
    let page_size_log2 = *cd.get(39).ok_or_else(|| fail("CodeDirectory too small"))?;

    if hash_type != CS_HASHTYPE_SHA256 {
        return Err(fail(format!(
            "only SHA-256 signatures can be verified (hash type {hash_type})"
        )));
    }
    if usize::from(hash_size) != HASH_SIZE {
        return Err(fail(format!("unexpected hash size {hash_size}")));
    }
    if page_size_log2 == 0 || page_size_log2 > 31 {
        return Err(fail(format!("invalid page size 2^{page_size_log2}")));
    }
    let page_size = 1usize << page_size_log2;

    if code_limit != sig_start {
        return Err(fail(format!(
            "codeLimit ({code_limit}) does not match the signature offset ({sig_start})"
        )));
    }
    let expected_slots = code_limit.div_ceil(page_size as u64);
    if u64::from(n_code_slots) != expected_slots {
        return Err(fail(format!(
            "nCodeSlots is {n_code_slots} but {expected_slots} pages are required"
        )));
    }

    // Identifier.
    let ident_bytes = cd
        .get(ident_offset..)
        .ok_or_else(|| fail("identifier offset out of bounds"))?;
    let ident_end = ident_bytes
        .iter()
        .position(|&byte| byte == 0)
        .ok_or_else(|| fail("identifier is not NUL-terminated"))?;
    let identifier = String::from_utf8_lossy(&ident_bytes[..ident_end]).into_owned();

    // Hash table bounds.
    let special_size = n_special_slots as usize * HASH_SIZE;
    if hash_offset < special_size {
        return Err(fail("special slot hashes extend before the CodeDirectory"));
    }
    let code_hashes = cd
        .get(hash_offset..hash_offset + n_code_slots as usize * HASH_SIZE)
        .ok_or_else(|| fail("code hash table out of bounds"))?;

    // Recompute and compare every code page hash.
    for (index, page) in data[..code_limit as usize].chunks(page_size).enumerate() {
        let digest = Sha256::digest(page);
        let stored = &code_hashes[index * HASH_SIZE..(index + 1) * HASH_SIZE];
        if digest.as_slice() != stored {
            return Err(fail(format!("code page {index} hash mismatch")));
        }
    }

    // Verify the special slot hashes for every blob that occupies one.
    let mut has_entitlements = false;
    for entry in blob::iter_superblob(sig).ok_or_else(|| fail("invalid SuperBlob"))? {
        if entry.slot == 0 || entry.slot > n_special_slots {
            continue;
        }
        let (_, blob_data) = blob::find_blob(sig, entry.slot)
            .ok_or_else(|| fail(format!("blob for slot {} out of bounds", entry.slot)))?;
        if entry.slot == CSSLOT_ENTITLEMENTS {
            has_entitlements = true;
        }
        let digest = Sha256::digest(blob_data);
        let stored_offset = hash_offset - entry.slot as usize * HASH_SIZE;
        let stored = &cd[stored_offset..stored_offset + HASH_SIZE];
        if digest.as_slice() != stored {
            return Err(fail(format!("special slot {} hash mismatch", entry.slot)));
        }
    }

    Ok(SignatureInfo {
        identifier,
        flags,
        code_limit,
        n_code_slots,
        n_special_slots,
        cd_hash: Sha256::digest(cd).into(),
        has_entitlements,
    })
}
