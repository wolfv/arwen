//! Minimal, bounds-checked Mach-O parsing for code signing.
//!
//! This module deliberately parses only the small subset of the Mach-O format
//! that code signing needs (the header, `LC_SEGMENT{,_64}` and
//! `LC_CODE_SIGNATURE` load commands). All reads are bounds-checked so that
//! malformed or truncated input produces an error instead of a panic.

use crate::error::SignError;

pub(crate) const MH_MAGIC: u32 = 0xfeed_face;
pub(crate) const MH_MAGIC_64: u32 = 0xfeed_facf;
pub(crate) const FAT_MAGIC: u32 = 0xcafe_babe;
pub(crate) const FAT_MAGIC_64: u32 = 0xcafe_babf;

pub(crate) const LC_SEGMENT: u32 = 0x1;
pub(crate) const LC_SEGMENT_64: u32 = 0x19;
pub(crate) const LC_CODE_SIGNATURE: u32 = 0x1d;

/// `MH_EXECUTE`: the file is a main executable.
pub(crate) const MH_EXECUTE: u32 = 0x2;

/// Size of a `linkedit_data_command` (`LC_CODE_SIGNATURE`).
pub(crate) const LC_CODE_SIGNATURE_SIZE: usize = 16;

/// Upper bound on `sizeofcmds` that we are willing to buffer. Real binaries
/// have load commands in the tens of kilobytes; 16 MiB is a generous sanity
/// limit that protects the streaming signer from unbounded buffering when fed
/// garbage.
pub(crate) const MAX_SIZEOFCMDS: usize = 16 * 1024 * 1024;

/// The kind of Mach-O file, as determined from the first four bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachOKind {
    /// A thin 32-bit Mach-O binary.
    Thin32 {
        /// Whether the binary is little-endian.
        little_endian: bool,
    },
    /// A thin 64-bit Mach-O binary.
    Thin64 {
        /// Whether the binary is little-endian.
        little_endian: bool,
    },
    /// A fat (universal) binary containing multiple architecture slices.
    Fat,
    /// A fat (universal) binary with 64-bit fat headers.
    Fat64,
}

impl MachOKind {
    /// Whether this is a thin (single-architecture) Mach-O binary.
    pub fn is_thin(&self) -> bool {
        matches!(self, MachOKind::Thin32 { .. } | MachOKind::Thin64 { .. })
    }

    pub(crate) fn header_size(&self) -> usize {
        match self {
            MachOKind::Thin32 { .. } => 28,
            MachOKind::Thin64 { .. } => 32,
            // Fat header: magic + nfat_arch
            MachOKind::Fat | MachOKind::Fat64 => 8,
        }
    }

    pub(crate) fn little_endian(&self) -> bool {
        match self {
            MachOKind::Thin32 { little_endian } | MachOKind::Thin64 { little_endian } => {
                *little_endian
            }
            // Fat headers are always big-endian.
            MachOKind::Fat | MachOKind::Fat64 => false,
        }
    }
}

/// Classify the first bytes of a file as a Mach-O binary (or not).
///
/// Returns `None` if `bytes` is shorter than four bytes or does not start
/// with a known Mach-O magic number.
pub fn macho_kind(bytes: &[u8]) -> Option<MachOKind> {
    let magic_bytes: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    let le = u32::from_le_bytes(magic_bytes);
    let be = u32::from_be_bytes(magic_bytes);
    match (le, be) {
        (MH_MAGIC_64, _) => Some(MachOKind::Thin64 {
            little_endian: true,
        }),
        (_, MH_MAGIC_64) => Some(MachOKind::Thin64 {
            little_endian: false,
        }),
        (MH_MAGIC, _) => Some(MachOKind::Thin32 {
            little_endian: true,
        }),
        (_, MH_MAGIC) => Some(MachOKind::Thin32 {
            little_endian: false,
        }),
        (_, FAT_MAGIC) => Some(MachOKind::Fat),
        (_, FAT_MAGIC_64) => Some(MachOKind::Fat64),
        _ => None,
    }
}

fn oob(what: &str) -> SignError {
    SignError::Malformed(format!("unexpected end of data while reading {what}"))
}

pub(crate) fn read_u32(data: &[u8], offset: usize, le: bool, what: &str) -> Result<u32, SignError> {
    let bytes: [u8; 4] = data
        .get(offset..offset + 4)
        .ok_or_else(|| oob(what))?
        .try_into()
        .expect("slice is 4 bytes");
    Ok(if le {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    })
}

pub(crate) fn read_u64(data: &[u8], offset: usize, le: bool, what: &str) -> Result<u64, SignError> {
    let bytes: [u8; 8] = data
        .get(offset..offset + 8)
        .ok_or_else(|| oob(what))?
        .try_into()
        .expect("slice is 8 bytes");
    Ok(if le {
        u64::from_le_bytes(bytes)
    } else {
        u64::from_be_bytes(bytes)
    })
}

pub(crate) fn write_u32(
    data: &mut [u8],
    offset: usize,
    value: u32,
    le: bool,
) -> Result<(), SignError> {
    let target = data
        .get_mut(offset..offset + 4)
        .ok_or_else(|| oob("write target"))?;
    target.copy_from_slice(&if le {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    });
    Ok(())
}

pub(crate) fn write_u64(
    data: &mut [u8],
    offset: usize,
    value: u64,
    le: bool,
) -> Result<(), SignError> {
    let target = data
        .get_mut(offset..offset + 8)
        .ok_or_else(|| oob("write target"))?;
    target.copy_from_slice(&if le {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    });
    Ok(())
}

/// The `LC_CODE_SIGNATURE` load command of a binary.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CodeSigCmd {
    /// File offset of the load command itself.
    pub cmd_offset: usize,
    /// File offset of the signature data (`dataoff`).
    pub data_offset: u32,
    /// Size of the signature data (`datasize`).
    pub data_size: u32,
}

/// The `__LINKEDIT` segment load command of a binary.
#[derive(Debug, Clone, Copy)]
pub(crate) struct LinkeditCmd {
    /// File offset of the load command itself.
    pub cmd_offset: usize,
    /// File offset of the segment (`fileoff`).
    pub fileoff: u64,
    /// File size of the segment (`filesize`).
    pub filesize: u64,
}

/// Information extracted from the Mach-O header and load commands that is
/// needed for code signing.
#[derive(Debug, Clone)]
pub(crate) struct LoadInfo {
    pub little_endian: bool,
    pub is_64bit: bool,
    pub header_size: usize,
    pub ncmds: u32,
    pub sizeofcmds: usize,
    pub is_executable: bool,
    pub codesig: Option<CodeSigCmd>,
    pub linkedit: Option<LinkeditCmd>,
    pub text_fileoff: u64,
    pub text_filesize: u64,
    /// The smallest non-zero file offset of any section; used to determine
    /// how much zero padding is available after the load commands.
    pub first_section_offset: u64,
}

impl LoadInfo {
    /// End of the load commands region (`header + sizeofcmds`).
    pub fn load_commands_end(&self) -> usize {
        self.header_size + self.sizeofcmds
    }

    /// Number of bytes of `data` that must be available (and buffered) to
    /// patch the load commands: the load commands themselves plus room for an
    /// inserted `LC_CODE_SIGNATURE` if the binary does not have one yet.
    pub fn required_prefix_len(&self) -> usize {
        if self.codesig.is_none() {
            self.load_commands_end() + LC_CODE_SIGNATURE_SIZE
        } else {
            self.load_commands_end()
        }
    }
}

/// Parse the Mach-O header, returning `(kind, sizeofcmds)`.
///
/// `data` must contain at least the full header.
pub(crate) fn parse_header(data: &[u8]) -> Result<(MachOKind, usize), SignError> {
    let kind = macho_kind(data).ok_or(SignError::NotMachO)?;
    match kind {
        MachOKind::Fat | MachOKind::Fat64 => Ok((kind, 0)),
        _ => {
            let le = kind.little_endian();
            if data.len() < kind.header_size() {
                return Err(oob("Mach-O header"));
            }
            let sizeofcmds = read_u32(data, 20, le, "sizeofcmds")? as usize;
            if sizeofcmds > MAX_SIZEOFCMDS {
                return Err(SignError::Malformed(format!(
                    "sizeofcmds ({sizeofcmds}) exceeds the maximum supported size"
                )));
            }
            Ok((kind, sizeofcmds))
        }
    }
}

/// Parse the header and load commands of a thin Mach-O binary.
///
/// `data` must contain at least `header + sizeofcmds` bytes; extra bytes are
/// ignored.
pub(crate) fn parse_load_info(data: &[u8]) -> Result<LoadInfo, SignError> {
    let (kind, sizeofcmds) = parse_header(data)?;
    let (is_64bit, le) = match kind {
        MachOKind::Thin64 { little_endian } => (true, little_endian),
        MachOKind::Thin32 { little_endian } => (false, little_endian),
        MachOKind::Fat => {
            return Err(SignError::Malformed(
                "expected a thin Mach-O binary, found a fat binary".into(),
            ))
        }
        MachOKind::Fat64 => return Err(SignError::Fat64Unsupported),
    };
    let header_size = kind.header_size();
    let ncmds = read_u32(data, 16, le, "ncmds")?;
    let filetype = read_u32(data, 12, le, "filetype")?;

    let cmds_end = header_size + sizeofcmds;
    if data.len() < cmds_end {
        return Err(oob("load commands"));
    }

    let mut info = LoadInfo {
        little_endian: le,
        is_64bit,
        header_size,
        ncmds,
        sizeofcmds,
        is_executable: filetype == MH_EXECUTE,
        codesig: None,
        linkedit: None,
        text_fileoff: 0,
        text_filesize: 0,
        first_section_offset: u64::MAX,
    };

    let mut offset = header_size;
    for _ in 0..ncmds {
        let cmd = read_u32(data, offset, le, "load command type")?;
        let cmdsize = read_u32(data, offset + 4, le, "load command size")? as usize;
        if cmdsize < 8 || offset + cmdsize > cmds_end {
            return Err(SignError::Malformed(format!(
                "load command at offset {offset} has invalid size {cmdsize}"
            )));
        }

        match cmd {
            LC_CODE_SIGNATURE => {
                if cmdsize < LC_CODE_SIGNATURE_SIZE {
                    return Err(SignError::Malformed(
                        "LC_CODE_SIGNATURE command is too small".into(),
                    ));
                }
                info.codesig = Some(CodeSigCmd {
                    cmd_offset: offset,
                    data_offset: read_u32(data, offset + 8, le, "code signature dataoff")?,
                    data_size: read_u32(data, offset + 12, le, "code signature datasize")?,
                });
            }
            LC_SEGMENT_64 | LC_SEGMENT => {
                parse_segment(data, offset, cmdsize, cmd == LC_SEGMENT_64, le, &mut info)?;
            }
            _ => {}
        }

        offset += cmdsize;
    }

    // If no section provides a lower bound for header padding, fall back to
    // the start of the __LINKEDIT segment (load commands always precede it).
    if info.first_section_offset == u64::MAX {
        info.first_section_offset = info.linkedit.map(|l| l.fileoff).unwrap_or(cmds_end as u64);
    }

    Ok(info)
}

fn parse_segment(
    data: &[u8],
    offset: usize,
    cmdsize: usize,
    is_64bit: bool,
    le: bool,
    info: &mut LoadInfo,
) -> Result<(), SignError> {
    // segment_command{,_64} layout:
    //   cmd, cmdsize, segname[16],
    //   vmaddr, vmsize, fileoff, filesize (u32 or u64 each),
    //   maxprot, initprot, nsects, flags
    let (seg_cmd_size, sect_size) = if is_64bit { (72, 80) } else { (56, 68) };
    if cmdsize < seg_cmd_size {
        return Err(SignError::Malformed(
            "segment load command is too small".into(),
        ));
    }
    let segname = data
        .get(offset + 8..offset + 24)
        .ok_or_else(|| oob("segment name"))?;
    let segname = core::str::from_utf8(segname)
        .unwrap_or("")
        .trim_end_matches('\0');

    let (fileoff, filesize, nsects) = if is_64bit {
        (
            read_u64(data, offset + 40, le, "segment fileoff")?,
            read_u64(data, offset + 48, le, "segment filesize")?,
            read_u32(data, offset + 64, le, "segment nsects")?,
        )
    } else {
        (
            u64::from(read_u32(data, offset + 32, le, "segment fileoff")?),
            u64::from(read_u32(data, offset + 36, le, "segment filesize")?),
            read_u32(data, offset + 48, le, "segment nsects")?,
        )
    };

    match segname {
        "__LINKEDIT" => {
            info.linkedit = Some(LinkeditCmd {
                cmd_offset: offset,
                fileoff,
                filesize,
            });
        }
        "__TEXT" => {
            info.text_fileoff = fileoff;
            info.text_filesize = filesize;
        }
        _ => {}
    }

    // Track the smallest non-zero section file offset to know how much
    // padding is available after the load commands.
    let nsects = nsects as usize;
    if nsects
        .checked_mul(sect_size)
        .and_then(|s| s.checked_add(seg_cmd_size))
        .is_none_or(|total| total > cmdsize)
    {
        return Err(SignError::Malformed(format!(
            "segment {segname} declares more sections than fit in its load command"
        )));
    }
    // The section file offset lives at +48 (64-bit) / +40 (32-bit) within
    // each section entry.
    let sect_off_field = if is_64bit { 48 } else { 40 };
    for i in 0..nsects {
        let sect_offset = offset + seg_cmd_size + i * sect_size;
        let file_offset = read_u32(data, sect_offset + sect_off_field, le, "section offset")?;
        if file_offset > 0 {
            info.first_section_offset = info.first_section_offset.min(u64::from(file_offset));
        }
    }

    Ok(())
}

/// Insert an `LC_CODE_SIGNATURE` load command into the zero padding after the
/// existing load commands, updating `ncmds` and `sizeofcmds` in the header.
///
/// Returns the offset of the inserted command.
pub(crate) fn insert_codesig_cmd(
    prefix: &mut [u8],
    info: &LoadInfo,
    data_offset: u32,
) -> Result<usize, SignError> {
    let le = info.little_endian;
    let insert_at = info.load_commands_end();
    let insert_end = insert_at + LC_CODE_SIGNATURE_SIZE;

    if insert_end as u64 > info.first_section_offset {
        return Err(SignError::InsufficientHeaderPadding);
    }
    if insert_end > prefix.len() {
        return Err(SignError::Malformed(
            "load command area extends past the end of the binary".into(),
        ));
    }

    write_u32(prefix, insert_at, LC_CODE_SIGNATURE, le)?;
    write_u32(prefix, insert_at + 4, LC_CODE_SIGNATURE_SIZE as u32, le)?;
    write_u32(prefix, insert_at + 8, data_offset, le)?;
    // datasize is patched later, together with the pre-existing command case.
    write_u32(prefix, insert_at + 12, 0, le)?;

    // ncmds is at offset 16, sizeofcmds at offset 20 for both 32/64-bit.
    write_u32(prefix, 16, info.ncmds + 1, le)?;
    write_u32(
        prefix,
        20,
        (info.sizeofcmds + LC_CODE_SIGNATURE_SIZE) as u32,
        le,
    )?;

    Ok(insert_at)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_magics() {
        assert_eq!(
            macho_kind(&[0xcf, 0xfa, 0xed, 0xfe]),
            Some(MachOKind::Thin64 {
                little_endian: true
            })
        );
        assert_eq!(
            macho_kind(&[0xfe, 0xed, 0xfa, 0xcf]),
            Some(MachOKind::Thin64 {
                little_endian: false
            })
        );
        assert_eq!(
            macho_kind(&[0xce, 0xfa, 0xed, 0xfe]),
            Some(MachOKind::Thin32 {
                little_endian: true
            })
        );
        assert_eq!(macho_kind(&[0xca, 0xfe, 0xba, 0xbe]), Some(MachOKind::Fat));
        assert_eq!(
            macho_kind(&[0xca, 0xfe, 0xba, 0xbf]),
            Some(MachOKind::Fat64)
        );
        assert_eq!(macho_kind(&[0x7f, b'E', b'L', b'F']), None);
        assert_eq!(macho_kind(&[0xcf]), None);
        assert_eq!(macho_kind(&[]), None);
    }

    #[test]
    fn truncated_input_does_not_panic() {
        // Valid magic but nothing else.
        let data = [0xcf, 0xfa, 0xed, 0xfe];
        assert!(parse_load_info(&data).is_err());

        // Header claims load commands that are not there.
        let mut data = vec![0u8; 32];
        data[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        data[16..20].copy_from_slice(&5u32.to_le_bytes()); // ncmds
        data[20..24].copy_from_slice(&1024u32.to_le_bytes()); // sizeofcmds
        assert!(parse_load_info(&data).is_err());
    }

    #[test]
    fn zero_sized_load_command_is_rejected() {
        // A load command with cmdsize == 0 must not hang or panic.
        let mut data = vec![0u8; 64];
        data[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        data[16..20].copy_from_slice(&2u32.to_le_bytes()); // ncmds
        data[20..24].copy_from_slice(&32u32.to_le_bytes()); // sizeofcmds
                                                            // first command: cmd = 0, cmdsize = 0
        assert!(matches!(
            parse_load_info(&data),
            Err(SignError::Malformed(_))
        ));
    }
}
