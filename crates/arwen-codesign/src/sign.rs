//! Ad-hoc signing implementations: the streaming signer, in-memory signing
//! (including fat binaries) and the atomic file-based API.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::blob;
use crate::constants::CS_PAGE_SIZE;
use crate::error::SignError;
use crate::layout::{Layout, HASH_SIZE};
use crate::macho::{self, LoadInfo, MachOKind};
use crate::{AdhocSignOptions, Entitlements};

/// I/O buffer size used by [`adhoc_sign_file`].
const FILE_BUFFER_SIZE: usize = 256 * 1024;

/// Sanity cap for reading an existing signature blob when preserving
/// entitlements. Real signatures are at most a few MiB.
const MAX_EXISTING_SIGNATURE_SIZE: u32 = 16 * 1024 * 1024;

/// The result of preparing a binary's header for signing.
pub(crate) struct Prepared {
    pub layout: Layout,
    /// The input must provide at least this many bytes of original content
    /// (the start of the old signature region, or the end of `__LINKEDIT`
    /// for unsigned binaries).
    pub min_input: u64,
}

/// Patch the header + load commands in `prefix` so they describe the new
/// signature, and compute the signature layout.
///
/// `prefix` must be at least [`LoadInfo::required_prefix_len`] bytes long.
pub(crate) fn prepare(
    prefix: &mut [u8],
    info: &LoadInfo,
    identifier: &str,
    hardened_runtime: bool,
    linker_signed: bool,
    entitlements: Option<Vec<u8>>,
) -> Result<Prepared, SignError> {
    let le = info.little_endian;
    let linkedit = info.linkedit.ok_or(SignError::MissingLinkedit)?;

    let (cmd_offset, code_limit, min_input) = match info.codesig {
        // The binary is already signed: the new signature replaces the old
        // one at the same offset.
        Some(cs) => (
            cs.cmd_offset,
            u64::from(cs.data_offset),
            u64::from(cs.data_offset),
        ),
        // The binary is unsigned: append a signature at the end of
        // __LINKEDIT, aligned to 16 bytes like Apple's codesign_allocate.
        None => {
            let linkedit_end = linkedit
                .fileoff
                .checked_add(linkedit.filesize)
                .ok_or_else(|| SignError::Malformed("__LINKEDIT segment overflows".into()))?;
            let code_limit = linkedit_end.next_multiple_of(16);
            let data_offset = u32::try_from(code_limit).map_err(|_| {
                SignError::TooLarge("code signature would start beyond the 4 GiB limit".into())
            })?;
            let cmd_offset = macho::insert_codesig_cmd(prefix, info, data_offset)?;
            (cmd_offset, code_limit, linkedit_end)
        }
    };

    if code_limit < info.required_prefix_len() as u64 {
        return Err(SignError::Malformed(
            "code signature region overlaps the load commands".into(),
        ));
    }

    let layout = Layout::compute(
        info,
        code_limit,
        identifier,
        hardened_runtime,
        linker_signed,
        entitlements,
    )?;

    // Patch LC_CODE_SIGNATURE dataoff/datasize.
    macho::write_u32(prefix, cmd_offset + 8, code_limit as u32, le)?;
    macho::write_u32(prefix, cmd_offset + 12, layout.allocated_size as u32, le)?;

    // Patch __LINKEDIT filesize and vmsize so the file ends exactly at the
    // end of the signature (a kernel requirement).
    let (filesize, vmsize) = layout.linkedit_sizes(linkedit.fileoff)?;
    if info.is_64bit {
        macho::write_u64(prefix, linkedit.cmd_offset + 32, vmsize, le)?;
        macho::write_u64(prefix, linkedit.cmd_offset + 48, filesize, le)?;
    } else {
        let vmsize = u32::try_from(vmsize).map_err(|_| {
            SignError::TooLarge("__LINKEDIT vmsize exceeds 4 GiB in a 32-bit binary".into())
        })?;
        let filesize = u32::try_from(filesize).map_err(|_| {
            SignError::TooLarge("__LINKEDIT filesize exceeds 4 GiB in a 32-bit binary".into())
        })?;
        macho::write_u32(prefix, linkedit.cmd_offset + 24, vmsize, le)?;
        macho::write_u32(prefix, linkedit.cmd_offset + 36, filesize, le)?;
    }

    Ok(Prepared { layout, min_input })
}

// There is exactly one `State` per signer, so the variant size difference is
// irrelevant and not worth a heap allocation.
#[allow(clippy::large_enum_variant)]
enum State {
    /// Accumulating the header and load commands.
    Buffering { buf: Vec<u8> },
    /// Header patched and written; hashing code pages as they stream through.
    Streaming {
        layout: Layout,
        min_input: u64,
        hasher: Sha256,
        page_hashes: Vec<u8>,
        position: u64,
    },
}

/// A [`Write`] adapter that ad-hoc signs a thin Mach-O binary in a single
/// streaming pass.
///
/// Bytes written to the signer are forwarded to the inner writer with the
/// header and load commands patched for the new signature, and every 4 KiB
/// code page is hashed on the fly. Calling [`finish`](Self::finish) appends
/// the signature blob and returns the inner writer.
///
/// This allows combining "copy/transform a binary" and "re-sign it" into a
/// single read and a single write of the file, instead of the
/// write-then-rewrite that `codesign` requires.
///
/// Any bytes of an *existing* signature at the end of the input are consumed
/// and discarded (the new signature replaces them).
///
/// # Limitations
///
/// * Fat (universal) binaries are rejected with
///   [`SignError::FatBinaryNotStreamable`]; use [`adhoc_sign`] for those.
/// * [`Entitlements::Preserve`] is rejected with
///   [`SignError::CannotPreserveWhenStreaming`] because the existing
///   entitlements live at the end of the input. Extract them up front with
///   [`extract_entitlements`](crate::extract_entitlements) and pass them as
///   [`Entitlements::Custom`].
///
/// # Example
///
/// ```no_run
/// use std::io::Write;
/// use arwen_codesign::{AdhocSignOptions, StreamingSigner};
///
/// let input = std::fs::File::open("libfoo.dylib")?;
/// let output = std::fs::File::create("signed/libfoo.dylib")?;
///
/// let options = AdhocSignOptions::new("libfoo.dylib");
/// let mut signer = StreamingSigner::new(std::io::BufWriter::new(output), &options)?;
/// std::io::copy(&mut std::io::BufReader::new(input), &mut signer)?;
/// signer.finish()?.flush()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub struct StreamingSigner<W: Write> {
    inner: W,
    identifier: String,
    hardened_runtime: bool,
    linker_signed: bool,
    entitlements: Option<Vec<u8>>,
    state: State,
}

impl<W: Write> StreamingSigner<W> {
    /// Create a new streaming signer that writes the signed binary to
    /// `inner`.
    pub fn new(inner: W, options: &AdhocSignOptions<'_>) -> Result<Self, SignError> {
        let entitlements = match &options.entitlements {
            Entitlements::None => None,
            Entitlements::Custom(data) => Some(data.to_vec()),
            Entitlements::Preserve => return Err(SignError::CannotPreserveWhenStreaming),
        };
        Ok(StreamingSigner {
            inner,
            identifier: options.identifier.to_owned(),
            hardened_runtime: options.hardened_runtime,
            linker_signed: options.linker_signed,
            entitlements,
            state: State::Buffering { buf: Vec::new() },
        })
    }

    fn process(&mut self, data: &[u8]) -> Result<(), SignError> {
        match &mut self.state {
            State::Buffering { buf } => {
                buf.extend_from_slice(data);
                self.try_start()
            }
            State::Streaming { .. } => self.feed(data),
        }
    }

    /// Attempt to transition from buffering to streaming. Stays in the
    /// buffering state (without error) while the header and load commands
    /// are still incomplete.
    fn try_start(&mut self) -> Result<(), SignError> {
        let State::Buffering { buf } = &mut self.state else {
            return Ok(());
        };
        if buf.len() < 4 {
            return Ok(());
        }
        let kind = macho::macho_kind(buf).ok_or(SignError::NotMachO)?;
        match kind {
            MachOKind::Fat => return Err(SignError::FatBinaryNotStreamable),
            MachOKind::Fat64 => return Err(SignError::Fat64Unsupported),
            _ => {}
        }
        if buf.len() < kind.header_size() {
            return Ok(());
        }
        let (_, sizeofcmds) = macho::parse_header(buf)?;
        if buf.len() < kind.header_size() + sizeofcmds {
            return Ok(());
        }
        let info = macho::parse_load_info(buf)?;
        if buf.len() < info.required_prefix_len() {
            return Ok(());
        }

        // Everything needed to patch the header is available.
        let mut prefix = std::mem::take(buf);
        let rest = prefix.split_off(info.required_prefix_len());
        let prepared = prepare(
            &mut prefix,
            &info,
            &self.identifier,
            self.hardened_runtime,
            self.linker_signed,
            self.entitlements.take(),
        )?;
        let capacity = prepared.layout.n_code_slots * HASH_SIZE;
        self.state = State::Streaming {
            layout: prepared.layout,
            min_input: prepared.min_input,
            hasher: Sha256::new(),
            page_hashes: Vec::with_capacity(capacity),
            position: 0,
        };
        self.feed(&prefix)?;
        self.feed(&rest)
    }

    /// Hash and forward bytes, respecting 4 KiB page boundaries. Bytes at or
    /// beyond the code limit (the old signature) are discarded.
    fn feed(&mut self, mut chunk: &[u8]) -> Result<(), SignError> {
        let State::Streaming {
            layout,
            hasher,
            page_hashes,
            position,
            ..
        } = &mut self.state
        else {
            unreachable!("feed called while buffering");
        };
        let limit = layout.code_limit;
        let page_size = CS_PAGE_SIZE as u64;
        while !chunk.is_empty() && *position < limit {
            let page_end = (*position + page_size - *position % page_size).min(limit);
            let take = usize::try_from(page_end - *position)
                .unwrap_or(usize::MAX)
                .min(chunk.len());
            hasher.update(&chunk[..take]);
            self.inner.write_all(&chunk[..take])?;
            *position += take as u64;
            if *position == page_end {
                page_hashes.extend_from_slice(&hasher.finalize_reset());
            }
            chunk = &chunk[take..];
        }
        Ok(())
    }

    /// Finish signing: zero-pad up to the code limit if necessary, append
    /// the signature blob, and return the inner writer.
    ///
    /// The inner writer is *not* flushed; callers should flush it themselves
    /// if required.
    pub fn finish(mut self) -> Result<W, SignError> {
        // If the input ended while we were still buffering the header, give
        // a precise error.
        if let State::Buffering { buf } = &self.state {
            if buf.is_empty() || macho::macho_kind(buf).is_none() {
                return Err(SignError::NotMachO);
            }
            let expected = match macho::parse_header(buf) {
                Ok((kind, sizeofcmds)) => (kind.header_size() + sizeofcmds) as u64,
                Err(_) => 32,
            };
            return Err(SignError::TruncatedInput {
                expected,
                got: buf.len() as u64,
            });
        }

        let (min_input, limit, position) = match &self.state {
            State::Streaming {
                min_input,
                layout,
                position,
                ..
            } => (*min_input, layout.code_limit, *position),
            State::Buffering { .. } => unreachable!(),
        };
        if position < min_input {
            return Err(SignError::TruncatedInput {
                expected: min_input,
                got: position,
            });
        }

        // Zero-pad up to the (16-byte aligned) code limit. This only happens
        // for fresh signatures on binaries whose size is not 16-byte aligned.
        let zeros = [0u8; 16];
        let mut pos = position;
        while pos < limit {
            let take = usize::try_from(limit - pos)
                .unwrap_or(zeros.len())
                .min(zeros.len());
            self.feed(&zeros[..take])?;
            pos += take as u64;
        }

        let State::Streaming {
            layout,
            page_hashes,
            position,
            ..
        } = self.state
        else {
            unreachable!()
        };
        debug_assert_eq!(position, layout.code_limit);

        let blob = layout.build_blob(&page_hashes)?;
        let mut inner = self.inner;
        inner.write_all(&blob)?;
        Ok(inner)
    }

    /// Consume the signer and return the inner writer without completing the
    /// signature. The output written so far is not a valid binary.
    pub fn into_inner(self) -> W {
        self.inner
    }
}

impl<W: Write> Write for StreamingSigner<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.process(data).map_err(SignError::into_io_error)?;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Hash every 4 KiB page of `data` with SHA-256, returning the concatenated
/// digests. With the `parallel` feature enabled, pages are hashed on the
/// rayon thread pool.
fn hash_pages(data: &[u8]) -> Vec<u8> {
    let n_pages = data.len().div_ceil(CS_PAGE_SIZE);

    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;
        let mut hashes = vec![0u8; n_pages * HASH_SIZE];
        data.par_chunks(CS_PAGE_SIZE)
            .zip(hashes.par_chunks_mut(HASH_SIZE))
            .for_each(|(page, out)| out.copy_from_slice(&Sha256::digest(page)));
        hashes
    }

    #[cfg(not(feature = "parallel"))]
    {
        let mut hashes = Vec::with_capacity(n_pages * HASH_SIZE);
        for page in data.chunks(CS_PAGE_SIZE) {
            hashes.extend_from_slice(&Sha256::digest(page));
        }
        hashes
    }
}

/// Sign a thin Mach-O binary in memory.
fn sign_thin(mut data: Vec<u8>, options: &AdhocSignOptions<'_>) -> Result<Vec<u8>, SignError> {
    // Resolve entitlements while the old signature is still present.
    let entitlements = match &options.entitlements {
        Entitlements::None => None,
        Entitlements::Custom(custom) => Some(custom.to_vec()),
        Entitlements::Preserve => blob::extract_entitlements(&data),
    };

    let info = macho::parse_load_info(&data)?;
    let required = info.required_prefix_len();
    if data.len() < required {
        return Err(SignError::Malformed(
            "binary ends within its load command area".into(),
        ));
    }
    let prepared = prepare(
        &mut data[..required],
        &info,
        options.identifier,
        options.hardened_runtime,
        options.linker_signed,
        entitlements,
    )?;
    if (data.len() as u64) < prepared.min_input {
        return Err(SignError::TruncatedInput {
            expected: prepared.min_input,
            got: data.len() as u64,
        });
    }

    let layout = prepared.layout;
    let code_limit = usize::try_from(layout.code_limit)
        .map_err(|_| SignError::TooLarge("code limit does not fit in memory".into()))?;
    // Drop the old signature / zero-pad up to the aligned code limit.
    data.resize(code_limit, 0);

    let page_hashes = hash_pages(&data);
    let blob = layout.build_blob(&page_hashes)?;
    data.extend_from_slice(&blob);
    Ok(data)
}

/// Maximum number of architecture slices we accept in a fat binary.
const MAX_FAT_ARCHES: usize = 128;

#[derive(Debug, Clone, Copy)]
struct FatArch {
    cputype: u32,
    cpusubtype: u32,
    offset: u32,
    size: u32,
    align: u32,
}

/// Sign every architecture slice of a fat (universal) binary and reassemble
/// the fat container with the original per-slice alignment.
fn sign_fat(data: &[u8], options: &AdhocSignOptions<'_>) -> Result<Vec<u8>, SignError> {
    let n_arches = macho::read_u32(data, 4, false, "fat arch count")? as usize;
    if n_arches == 0 || n_arches > MAX_FAT_ARCHES {
        return Err(SignError::Malformed(format!(
            "fat binary declares {n_arches} architecture slices"
        )));
    }

    let mut arches = Vec::with_capacity(n_arches);
    for i in 0..n_arches {
        let base = 8 + i * 20;
        let arch = FatArch {
            cputype: macho::read_u32(data, base, false, "fat cputype")?,
            cpusubtype: macho::read_u32(data, base + 4, false, "fat cpusubtype")?,
            offset: macho::read_u32(data, base + 8, false, "fat slice offset")?,
            size: macho::read_u32(data, base + 12, false, "fat slice size")?,
            align: macho::read_u32(data, base + 16, false, "fat slice alignment")?,
        };
        if arch.align > 30 {
            return Err(SignError::Malformed(format!(
                "fat slice {i} has invalid alignment 2^{}",
                arch.align
            )));
        }
        if u64::from(arch.offset) + u64::from(arch.size) > data.len() as u64 {
            return Err(SignError::Malformed(format!(
                "fat slice {i} extends past the end of the file"
            )));
        }
        arches.push(arch);
    }

    // Sign each slice independently. `Entitlements::Preserve` is resolved
    // per slice by `sign_thin`.
    let mut signed = Vec::with_capacity(n_arches);
    for arch in &arches {
        let slice = data[arch.offset as usize..arch.offset as usize + arch.size as usize].to_vec();
        signed.push(sign_thin(slice, options)?);
    }

    // Recompute slice offsets: signing changes slice sizes.
    let header_size = 8 + n_arches * 20;
    let mut offsets = Vec::with_capacity(n_arches);
    let mut cursor = header_size as u64;
    for (arch, slice) in arches.iter().zip(&signed) {
        cursor = cursor.next_multiple_of(1u64 << arch.align);
        let end = cursor + slice.len() as u64;
        if end > u64::from(u32::MAX) {
            return Err(SignError::TooLarge(
                "signed fat binary exceeds the 4 GiB fat container limit".into(),
            ));
        }
        offsets.push(cursor);
        cursor = end;
    }

    let mut out = Vec::with_capacity(cursor as usize);
    out.extend_from_slice(&macho::FAT_MAGIC.to_be_bytes());
    out.extend_from_slice(&(n_arches as u32).to_be_bytes());
    for ((arch, slice), offset) in arches.iter().zip(&signed).zip(&offsets) {
        out.extend_from_slice(&arch.cputype.to_be_bytes());
        out.extend_from_slice(&arch.cpusubtype.to_be_bytes());
        out.extend_from_slice(&u32::try_from(*offset).expect("checked above").to_be_bytes());
        out.extend_from_slice(
            &u32::try_from(slice.len())
                .expect("checked above")
                .to_be_bytes(),
        );
        out.extend_from_slice(&arch.align.to_be_bytes());
    }
    for (slice, offset) in signed.iter().zip(&offsets) {
        out.resize(usize::try_from(*offset).expect("checked above"), 0);
        out.extend_from_slice(slice);
    }
    Ok(out)
}

/// Ad-hoc sign a Mach-O binary in memory.
///
/// Handles thin binaries as well as fat (universal) binaries, in which case
/// every architecture slice is signed and the fat container is reassembled.
///
/// # Example
///
/// ```no_run
/// use arwen_codesign::{adhoc_sign, AdhocSignOptions, Entitlements};
///
/// let data = std::fs::read("libfoo.dylib")?;
/// let options = AdhocSignOptions::new("libfoo.dylib")
///     .with_entitlements(Entitlements::Preserve);
/// let signed = adhoc_sign(data, &options)?;
/// std::fs::write("libfoo.dylib", signed)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn adhoc_sign(data: Vec<u8>, options: &AdhocSignOptions<'_>) -> Result<Vec<u8>, SignError> {
    match macho::macho_kind(&data) {
        None => Err(SignError::NotMachO),
        Some(MachOKind::Fat) => sign_fat(&data, options),
        Some(MachOKind::Fat64) => Err(SignError::Fat64Unsupported),
        Some(_) => sign_thin(data, options),
    }
}

/// Read the existing entitlements of the (thin Mach-O) file, if any.
fn extract_entitlements_from_file(
    file: &mut std::fs::File,
    file_len: u64,
) -> Result<Option<Vec<u8>>, SignError> {
    let mut header = [0u8; 32];
    file.seek(SeekFrom::Start(0))?;
    let mut read = 0;
    while read < header.len() {
        match file.read(&mut header[read..])? {
            0 => break,
            n => read += n,
        }
    }
    let header = &header[..read];

    let Some(kind) = macho::macho_kind(header) else {
        return Ok(None);
    };
    if !kind.is_thin() || header.len() < kind.header_size() {
        return Ok(None);
    }
    let Ok((_, sizeofcmds)) = macho::parse_header(header) else {
        return Ok(None);
    };
    let prefix_len = kind.header_size() + sizeofcmds;
    if prefix_len as u64 > file_len {
        return Ok(None);
    }

    let mut prefix = vec![0u8; prefix_len];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut prefix)?;
    let Ok(info) = macho::parse_load_info(&prefix) else {
        return Ok(None);
    };
    let Some(codesig) = info.codesig else {
        return Ok(None);
    };
    if codesig.data_size == 0
        || codesig.data_size > MAX_EXISTING_SIGNATURE_SIZE
        || u64::from(codesig.data_offset) + u64::from(codesig.data_size) > file_len
    {
        return Ok(None);
    }

    let mut sig = vec![0u8; codesig.data_size as usize];
    file.seek(SeekFrom::Start(u64::from(codesig.data_offset)))?;
    file.read_exact(&mut sig)?;
    Ok(blob::entitlements_from_superblob(&sig))
}

/// Ad-hoc sign a Mach-O binary file, replacing it atomically.
///
/// Thin binaries are signed in a single streaming pass without loading the
/// whole file into memory; fat (universal) binaries are signed in memory.
/// The original file permissions are preserved and the file is replaced via
/// an atomic rename, so a crash can never leave a half-signed binary behind.
///
/// # Example
///
/// ```no_run
/// use arwen_codesign::{adhoc_sign_file, AdhocSignOptions, Entitlements};
///
/// let options = AdhocSignOptions::new("libfoo.dylib")
///     .with_entitlements(Entitlements::Preserve);
/// adhoc_sign_file(std::path::Path::new("libfoo.dylib"), &options)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn adhoc_sign_file(path: &Path, options: &AdhocSignOptions<'_>) -> Result<(), SignError> {
    let mut file = std::fs::File::open(path)?;
    let metadata = file.metadata()?;

    let mut magic = [0u8; 4];
    let mut read = 0;
    while read < magic.len() {
        match file.read(&mut magic[read..])? {
            0 => break,
            n => read += n,
        }
    }
    let kind = macho::macho_kind(&magic[..read]).ok_or(SignError::NotMachO)?;

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;

    match kind {
        MachOKind::Fat64 => return Err(SignError::Fat64Unsupported),
        MachOKind::Fat => {
            let mut data = Vec::with_capacity(metadata.len() as usize);
            file.seek(SeekFrom::Start(0))?;
            file.read_to_end(&mut data)?;
            let signed = adhoc_sign(data, options)?;
            temp.as_file_mut().write_all(&signed)?;
        }
        MachOKind::Thin32 { .. } | MachOKind::Thin64 { .. } => {
            // Resolve `Entitlements::Preserve` up front; the streaming
            // signer cannot seek back to the old signature.
            let preserved;
            let entitlements = match &options.entitlements {
                Entitlements::None => Entitlements::None,
                Entitlements::Custom(custom) => Entitlements::Custom(custom),
                Entitlements::Preserve => {
                    preserved = extract_entitlements_from_file(&mut file, metadata.len())?;
                    match &preserved {
                        Some(entitlements) => Entitlements::Custom(entitlements),
                        None => Entitlements::None,
                    }
                }
            };
            let resolved_options = AdhocSignOptions {
                identifier: options.identifier,
                hardened_runtime: options.hardened_runtime,
                linker_signed: options.linker_signed,
                entitlements,
            };

            file.seek(SeekFrom::Start(0))?;
            let writer = io::BufWriter::with_capacity(FILE_BUFFER_SIZE, temp.as_file_mut());
            let mut signer = StreamingSigner::new(writer, &resolved_options)?;
            let mut reader = io::BufReader::with_capacity(FILE_BUFFER_SIZE, &mut file);
            io::copy(&mut reader, &mut signer)?;
            signer.finish()?.flush()?;
        }
    }

    // `NamedTempFile` is created with mode 0600: restore the original
    // permissions (notably the executable bit) before the atomic rename.
    temp.as_file().set_permissions(metadata.permissions())?;
    temp.persist(path).map_err(|err| SignError::Io(err.error))?;
    Ok(())
}
