//! Computation of the code signature layout and serialization of the
//! signature SuperBlob.
//!
//! The layout is fully determined by the signing options and the code limit
//! (the file offset at which the signature starts). This is what makes
//! single-pass streaming possible: all load command patches and the total
//! output size are known before a single code page has been hashed.

use crate::constants::*;
use crate::error::SignError;
use crate::macho::LoadInfo;

/// Size of the CodeDirectory header for version `0x20400`.
pub(crate) const CODEDIRECTORY_SIZE: usize = 88;

/// Size of an empty Requirements blob (magic + length + count).
const REQUIREMENTS_BLOB_SIZE: usize = 12;

/// Size of an empty CMS signature blob wrapper (magic + length).
const CMS_BLOB_SIZE: usize = 8;

/// Extra space reserved beyond the actual signature content. Apple's
/// `codesign` reserves generous slack as well (between ~1 KiB and ~18 KiB
/// depending on the version); the slack allows the signature to be replaced
/// in-place without rewriting the whole file.
const ALLOCATION_SLACK: usize = 1024;

/// `__LINKEDIT` vmsize is rounded up to 16 KiB pages, matching Apple's
/// `codesign` (and the maximum page size across x86_64/arm64).
const SEGMENT_PAGE_SIZE: u64 = 0x4000;

/// SHA-256 digest length.
pub(crate) const HASH_SIZE: usize = 32;

/// A fully computed code signature layout.
#[derive(Debug, Clone)]
pub(crate) struct Layout {
    /// File offset where the signature is placed; all bytes before it are
    /// covered by the page hashes.
    pub code_limit: u64,
    /// Number of 4 KiB code pages that will be hashed.
    pub n_code_slots: usize,
    /// Number of special (negative-index) hash slots.
    pub n_special_slots: u32,
    /// CodeDirectory flags (`CS_ADHOC`, ...).
    pub flags: u32,
    pub exec_seg_base: u64,
    pub exec_seg_limit: u64,
    pub exec_seg_flags: u64,
    /// Signature identifier (without NUL terminator).
    pub identifier: Vec<u8>,
    /// Entitlements plist data, if any.
    pub entitlements: Option<Vec<u8>>,
    /// Size of the actual SuperBlob content.
    pub blob_size: usize,
    /// Allocated size of the signature region (`>= blob_size`, 16-byte
    /// aligned); this is what `LC_CODE_SIGNATURE.datasize` is set to.
    pub allocated_size: usize,
}

impl Layout {
    /// Compute the signature layout for a binary.
    pub fn compute(
        info: &LoadInfo,
        code_limit: u64,
        identifier: &str,
        hardened_runtime: bool,
        linker_signed: bool,
        entitlements: Option<Vec<u8>>,
    ) -> Result<Layout, SignError> {
        if code_limit > u64::from(u32::MAX) {
            return Err(SignError::TooLarge(format!(
                "code signature would start at offset {code_limit}, beyond the 4 GiB limit"
            )));
        }

        let mut flags = CS_ADHOC;
        if hardened_runtime {
            flags |= CS_RUNTIME;
        }
        if linker_signed {
            flags |= CS_LINKER_SIGNED;
        }

        let n_code_slots = usize::try_from(code_limit.div_ceil(CS_PAGE_SIZE as u64))
            .expect("code_limit fits in u32");
        let n_special_slots = if entitlements.is_some() {
            CSSLOT_ENTITLEMENTS
        } else {
            CSSLOT_REQUIREMENTS
        };

        let identifier = identifier.as_bytes().to_vec();
        let layout = Layout {
            code_limit,
            n_code_slots,
            n_special_slots,
            flags,
            exec_seg_base: info.text_fileoff,
            exec_seg_limit: info.text_filesize,
            exec_seg_flags: if info.is_executable {
                CS_EXECSEG_MAIN_BINARY
            } else {
                0
            },
            identifier,
            entitlements,
            blob_size: 0,
            allocated_size: 0,
        };

        let blob_size = layout.superblob_header_size()
            + layout.codedirectory_size()
            + REQUIREMENTS_BLOB_SIZE
            + layout.entitlements_blob_size()
            + CMS_BLOB_SIZE;
        let allocated_size = (blob_size + ALLOCATION_SLACK).next_multiple_of(16);

        if u32::try_from(blob_size).is_err()
            || code_limit
                .checked_add(allocated_size as u64)
                .is_none_or(|end| end > u64::from(u32::MAX))
        {
            return Err(SignError::TooLarge(
                "signature blob does not fit within the first 4 GiB of the file".into(),
            ));
        }

        Ok(Layout {
            blob_size,
            allocated_size,
            ..layout
        })
    }

    /// Number of blobs in the SuperBlob.
    fn blob_count(&self) -> usize {
        if self.entitlements.is_some() {
            4
        } else {
            3
        }
    }

    /// SuperBlob header plus blob index entries.
    fn superblob_header_size(&self) -> usize {
        12 + self.blob_count() * 8
    }

    /// Total size of the CodeDirectory blob.
    fn codedirectory_size(&self) -> usize {
        CODEDIRECTORY_SIZE
            + self.identifier.len()
            + 1
            + self.n_special_slots as usize * HASH_SIZE
            + self.n_code_slots * HASH_SIZE
    }

    fn entitlements_blob_size(&self) -> usize {
        self.entitlements.as_ref().map_or(0, |e| 8 + e.len())
    }

    /// New file size of the signed binary (`code_limit + allocated_size`).
    pub fn signed_file_size(&self) -> u64 {
        self.code_limit + self.allocated_size as u64
    }

    /// New `__LINKEDIT` `filesize`/`vmsize` values.
    pub fn linkedit_sizes(&self, linkedit_fileoff: u64) -> Result<(u64, u64), SignError> {
        let filesize = self
            .signed_file_size()
            .checked_sub(linkedit_fileoff)
            .ok_or_else(|| {
                SignError::Malformed("__LINKEDIT segment starts after the code signature".into())
            })?;
        let vmsize = filesize.next_multiple_of(SEGMENT_PAGE_SIZE);
        Ok((filesize, vmsize))
    }

    /// Serialize the signature SuperBlob.
    ///
    /// `page_hashes` must contain exactly `n_code_slots` SHA-256 digests.
    /// The returned buffer has length `allocated_size` (content followed by
    /// zero padding).
    pub fn build_blob(&self, page_hashes: &[u8]) -> Result<Vec<u8>, SignError> {
        if page_hashes.len() != self.n_code_slots * HASH_SIZE {
            return Err(SignError::Malformed(format!(
                "internal error: expected {} page hashes, got {}",
                self.n_code_slots,
                page_hashes.len() / HASH_SIZE
            )));
        }

        let codedir_offset = self.superblob_header_size();
        let requirements_offset = codedir_offset + self.codedirectory_size();
        let entitlements_offset = requirements_offset + REQUIREMENTS_BLOB_SIZE;
        let cms_offset = entitlements_offset + self.entitlements_blob_size();

        let mut blob = vec![0u8; self.allocated_size];
        let mut w = BeWriter::new(&mut blob);

        // SuperBlob header.
        w.put_u32(CSMAGIC_EMBEDDED_SIGNATURE);
        w.put_u32(self.blob_size as u32);
        w.put_u32(self.blob_count() as u32);

        // Blob index.
        w.put_u32(CSSLOT_CODEDIRECTORY);
        w.put_u32(codedir_offset as u32);
        w.put_u32(CSSLOT_REQUIREMENTS);
        w.put_u32(requirements_offset as u32);
        if self.entitlements.is_some() {
            w.put_u32(CSSLOT_ENTITLEMENTS);
            w.put_u32(entitlements_offset as u32);
        }
        w.put_u32(CSSLOT_SIGNATURESLOT);
        w.put_u32(cms_offset as u32);

        // CodeDirectory (version 0x20400).
        let ident_offset = CODEDIRECTORY_SIZE;
        let hash_offset = CODEDIRECTORY_SIZE
            + self.identifier.len()
            + 1
            + self.n_special_slots as usize * HASH_SIZE;
        w.put_u32(CSMAGIC_CODEDIRECTORY);
        w.put_u32(self.codedirectory_size() as u32);
        w.put_u32(CS_VERSION);
        w.put_u32(self.flags);
        w.put_u32(hash_offset as u32);
        w.put_u32(ident_offset as u32);
        w.put_u32(self.n_special_slots);
        w.put_u32(self.n_code_slots as u32);
        w.put_u32(self.code_limit as u32);
        w.put_u8(HASH_SIZE as u8); // hashSize
        w.put_u8(CS_HASHTYPE_SHA256); // hashType
        w.put_u8(0); // platform
        w.put_u8(CS_PAGE_SIZE_LOG2); // pageSize (log2)
        w.put_u32(0); // spare2
        w.put_u32(0); // scatterOffset
        w.put_u32(0); // teamOffset
        w.put_u32(0); // spare3
        w.put_u64(0); // codeLimit64
        w.put_u64(self.exec_seg_base);
        w.put_u64(self.exec_seg_limit);
        w.put_u64(self.exec_seg_flags);

        // Identifier (NUL-terminated).
        w.put_bytes(&self.identifier);
        w.put_u8(0);

        // Special slot hashes, stored in reverse order (slot -N first).
        for slot in (1..=self.n_special_slots).rev() {
            if slot == CSSLOT_ENTITLEMENTS {
                if let Some(entitlements) = &self.entitlements {
                    w.put_bytes(&entitlements_blob_hash(entitlements));
                    continue;
                }
            }
            if slot == CSSLOT_REQUIREMENTS {
                w.put_bytes(&empty_requirements_hash());
            } else {
                w.skip(HASH_SIZE);
            }
        }

        // Code page hashes.
        w.put_bytes(page_hashes);

        // Empty Requirements blob.
        debug_assert_eq!(w.position(), requirements_offset);
        w.put_bytes(&empty_requirements_blob());

        // Entitlements blob.
        if let Some(entitlements) = &self.entitlements {
            debug_assert_eq!(w.position(), entitlements_offset);
            w.put_u32(CSMAGIC_EMBEDDED_ENTITLEMENTS);
            w.put_u32((8 + entitlements.len()) as u32);
            w.put_bytes(entitlements);
        }

        // Empty CMS signature wrapper.
        debug_assert_eq!(w.position(), cms_offset);
        w.put_u32(CSMAGIC_BLOBWRAPPER);
        w.put_u32(CMS_BLOB_SIZE as u32);

        debug_assert_eq!(w.position(), self.blob_size);
        Ok(blob)
    }
}

fn empty_requirements_blob() -> [u8; REQUIREMENTS_BLOB_SIZE] {
    let mut blob = [0u8; REQUIREMENTS_BLOB_SIZE];
    blob[..4].copy_from_slice(&CSMAGIC_REQUIREMENTS.to_be_bytes());
    blob[4..8].copy_from_slice(&(REQUIREMENTS_BLOB_SIZE as u32).to_be_bytes());
    // count = 0
    blob
}

fn empty_requirements_hash() -> [u8; HASH_SIZE] {
    use sha2::{Digest, Sha256};
    Sha256::digest(empty_requirements_blob()).into()
}

fn entitlements_blob_hash(entitlements: &[u8]) -> [u8; HASH_SIZE] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(CSMAGIC_EMBEDDED_ENTITLEMENTS.to_be_bytes());
    hasher.update(((8 + entitlements.len()) as u32).to_be_bytes());
    hasher.update(entitlements);
    hasher.finalize().into()
}

/// Simple big-endian cursor writer over a pre-allocated buffer.
struct BeWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> BeWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        BeWriter { buf, pos: 0 }
    }

    fn position(&self) -> usize {
        self.pos
    }

    fn put_u8(&mut self, value: u8) {
        self.buf[self.pos] = value;
        self.pos += 1;
    }

    fn put_u32(&mut self, value: u32) {
        self.buf[self.pos..self.pos + 4].copy_from_slice(&value.to_be_bytes());
        self.pos += 4;
    }

    fn put_u64(&mut self, value: u64) {
        self.buf[self.pos..self.pos + 8].copy_from_slice(&value.to_be_bytes());
        self.pos += 8;
    }

    fn put_bytes(&mut self, bytes: &[u8]) {
        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
    }

    fn skip(&mut self, n: usize) {
        self.pos += n;
    }
}
