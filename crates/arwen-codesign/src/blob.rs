//! Bounds-checked scanning of existing code signature SuperBlobs.

use crate::constants::*;
use crate::macho;

/// An entry of a SuperBlob index.
#[derive(Debug, Clone, Copy)]
pub(crate) struct BlobEntry {
    pub slot: u32,
    pub offset: usize,
}

fn be_u32(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        data.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

/// Iterate over the blob index entries of an embedded signature SuperBlob.
/// Returns `None` if the data is not a SuperBlob.
pub(crate) fn iter_superblob(sig: &[u8]) -> Option<impl Iterator<Item = BlobEntry> + '_> {
    if be_u32(sig, 0)? != CSMAGIC_EMBEDDED_SIGNATURE {
        return None;
    }
    let count = be_u32(sig, 8)? as usize;
    Some((0..count).filter_map(move |i| {
        let index_offset = 12 + i * 8;
        Some(BlobEntry {
            slot: be_u32(sig, index_offset)?,
            offset: be_u32(sig, index_offset + 4)? as usize,
        })
    }))
}

/// Find a blob with the given slot index and return `(magic, content)` where
/// `content` includes the 8-byte blob header.
pub(crate) fn find_blob(sig: &[u8], slot: u32) -> Option<(u32, &[u8])> {
    for entry in iter_superblob(sig)? {
        if entry.slot != slot {
            continue;
        }
        let magic = be_u32(sig, entry.offset)?;
        let length = be_u32(sig, entry.offset + 4)? as usize;
        if length < 8 {
            return None;
        }
        let content = sig.get(entry.offset..entry.offset.checked_add(length)?)?;
        return Some((magic, content));
    }
    None
}

/// Extract the entitlements plist from a signature SuperBlob.
pub(crate) fn entitlements_from_superblob(sig: &[u8]) -> Option<Vec<u8>> {
    let (magic, blob) = find_blob(sig, CSSLOT_ENTITLEMENTS)?;
    if magic != CSMAGIC_EMBEDDED_ENTITLEMENTS {
        return None;
    }
    Some(blob[8..].to_vec())
}

/// Check whether the CodeDirectory of a signature SuperBlob has the
/// `CS_LINKER_SIGNED` flag.
pub(crate) fn linker_signed_from_superblob(sig: &[u8]) -> bool {
    let Some((magic, blob)) = find_blob(sig, CSSLOT_CODEDIRECTORY) else {
        return false;
    };
    if magic != CSMAGIC_CODEDIRECTORY {
        return false;
    }
    match be_u32(blob, 12) {
        Some(flags) => flags & CS_LINKER_SIGNED != 0,
        None => false,
    }
}

/// Locate the embedded signature SuperBlob of a thin Mach-O binary.
pub(crate) fn signature_of(data: &[u8]) -> Option<&[u8]> {
    if !macho::macho_kind(data)?.is_thin() {
        return None;
    }
    let info = macho::parse_load_info(data).ok()?;
    let codesig = info.codesig?;
    if codesig.data_size == 0 {
        return None;
    }
    let start = codesig.data_offset as usize;
    data.get(start..start.checked_add(codesig.data_size as usize)?)
}

/// Extract the entitlements plist embedded in the code signature of a thin
/// Mach-O binary.
///
/// Returns `None` if the binary is not a thin Mach-O binary, is not signed,
/// or its signature carries no entitlements. This is the building block for
/// implementing `codesign --preserve-metadata=entitlements` behavior: extract
/// them from the original binary and pass them to the signer as
/// [`crate::Entitlements::Custom`].
pub fn extract_entitlements(data: &[u8]) -> Option<Vec<u8>> {
    entitlements_from_superblob(signature_of(data)?)
}

/// Check whether a thin Mach-O binary carries a linker-generated ad-hoc
/// signature (`CS_LINKER_SIGNED`).
///
/// Returns `false` for unsigned binaries, fat binaries, and non-Mach-O data.
pub fn is_linker_signed(data: &[u8]) -> bool {
    match signature_of(data) {
        Some(sig) => linker_signed_from_superblob(sig),
        None => false,
    }
}
