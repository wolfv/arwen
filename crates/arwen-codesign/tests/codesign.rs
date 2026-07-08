//! Integration tests for ad-hoc signing.
//!
//! The fixtures in `tests/data/macho/codesign` include binaries signed by
//! Apple's real `codesign` tool (`test_exe_adhoc`, `test_exe_hardened`, the
//! `conda-repackaged` binaries) and a linker-signed binary. The [`verify`]
//! function is validated against those, and the signers are then validated
//! against [`verify`]. All of this runs on any host platform.

use std::io::Write;
use std::path::{Path, PathBuf};

use arwen_codesign::constants::{CS_ADHOC, CS_LINKER_SIGNED, CS_RUNTIME};
use arwen_codesign::{
    adhoc_sign, adhoc_sign_file, extract_entitlements, is_linker_signed, verify, AdhocSignOptions,
    Entitlements, SignError, StreamingSigner,
};
use rstest::rstest;

fn data_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/data/macho/codesign")
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(data_dir().join(name)).unwrap()
}

const TEST_ENTITLEMENTS: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.get-task-allow</key>
    <true/>
</dict>
</plist>
"#;

/// Sign through the streaming signer, feeding the input in chunks of the
/// given size.
fn streaming_sign(data: &[u8], options: &AdhocSignOptions<'_>, chunk_size: usize) -> Vec<u8> {
    let mut signer = StreamingSigner::new(Vec::new(), options).unwrap();
    for chunk in data.chunks(chunk_size) {
        signer.write_all(chunk).unwrap();
    }
    signer.finish().unwrap()
}

// ---------------------------------------------------------------------------
// The verifier must accept binaries signed by Apple's codesign and by the
// linker; this is what gives the rest of the tests their teeth.
// ---------------------------------------------------------------------------

#[rstest]
#[case::codesign_adhoc("test_exe_adhoc", "com.test.exe", CS_ADHOC)]
#[case::codesign_hardened("test_exe_hardened", "com.test.exe", CS_ADHOC | CS_RUNTIME)]
#[case::linker_signed(
    "test_exe_linker_signed",
    "test_exe_linker_signed",
    CS_ADHOC | CS_LINKER_SIGNED
)]
#[case::conda_bzip2("conda-repackaged/bzip2", "bzip2", CS_ADHOC)]
#[case::conda_openssl("conda-repackaged/openssl", "openssl", CS_ADHOC)]
#[case::conda_zstd("conda-repackaged/zstd", "zstd", CS_ADHOC)]
#[case::conda_ruby("conda-repackaged/ruby", "ruby", CS_ADHOC)]
#[case::conda_xmllint("conda-repackaged/xmllint", "xmllint", CS_ADHOC)]
#[case::conda_patchelf("conda-repackaged/patchelf", "patchelf", CS_ADHOC)]
#[case::conda_maturin("conda-repackaged/maturin", "maturin", CS_ADHOC)]
#[case::conda_python("conda-repackaged/python3.13", "python3", CS_ADHOC)]
fn verify_accepts_apple_signed_fixtures(
    #[case] name: &str,
    #[case] identifier: &str,
    #[case] flags: u32,
) {
    let data = fixture(name);
    let infos = verify(&data).unwrap();
    assert_eq!(infos.len(), 1);
    // `codesign` sometimes derives a hash-suffixed identifier from the file
    // name (e.g. "patchelf-55554944..."), so only compare the prefix.
    assert!(
        infos[0].identifier == identifier
            || infos[0].identifier.starts_with(&format!("{identifier}-")),
        "unexpected identifier {:?}",
        infos[0].identifier
    );
    assert_eq!(infos[0].flags, flags);
}

#[test]
fn verify_rejects_tampered_binary() {
    let mut data = fixture("test_exe_adhoc");
    // Flip a byte in the middle of the code (well before the signature).
    data[0x2000] ^= 0xff;
    let err = verify(&data).unwrap_err();
    assert!(matches!(err, SignError::VerificationFailed(_)), "{err}");
}

#[test]
fn verify_rejects_unsigned_binary() {
    assert!(verify(&fixture("test_exe_unsigned")).is_err());
}

// ---------------------------------------------------------------------------
// In-memory signing.
// ---------------------------------------------------------------------------

#[rstest]
#[case::adhoc("test_exe_adhoc")]
#[case::hardened("test_exe_hardened")]
#[case::linker_signed("test_exe_linker_signed")]
#[case::unsigned("test_exe_unsigned")]
#[case::bzip2("conda-repackaged/bzip2")]
#[case::openssl("conda-repackaged/openssl")]
#[case::zstd("conda-repackaged/zstd")]
#[case::ruby("conda-repackaged/ruby")]
#[case::xmllint("conda-repackaged/xmllint")]
#[case::patchelf("conda-repackaged/patchelf")]
#[case::python("conda-repackaged/python3.13")]
#[case::maturin("conda-repackaged/maturin")]
fn adhoc_sign_produces_verifiable_signature(#[case] name: &str) {
    let data = fixture(name);
    let options = AdhocSignOptions::new("test.identifier");
    let signed = adhoc_sign(data, &options).unwrap();

    let infos = verify(&signed).unwrap();
    assert_eq!(infos.len(), 1);
    assert_eq!(infos[0].identifier, "test.identifier");
    assert_eq!(infos[0].flags, CS_ADHOC);
    assert_eq!(infos[0].n_special_slots, 2);
    assert!(!infos[0].has_entitlements);
}

#[test]
fn signing_is_idempotent() {
    let options = AdhocSignOptions::new("stable.identifier");
    let once = adhoc_sign(fixture("conda-repackaged/bzip2"), &options).unwrap();
    let twice = adhoc_sign(once.clone(), &options).unwrap();
    assert_eq!(
        once, twice,
        "re-signing with identical options must be a no-op"
    );
}

#[test]
fn signing_with_hardened_runtime_sets_flag() {
    let options = AdhocSignOptions::new("test").with_hardened_runtime();
    let signed = adhoc_sign(fixture("test_exe_adhoc"), &options).unwrap();
    assert_eq!(verify(&signed).unwrap()[0].flags, CS_ADHOC | CS_RUNTIME);
}

#[test]
fn signing_with_linker_signed_sets_flag() {
    let options = AdhocSignOptions::new("test").with_linker_signed();
    let signed = adhoc_sign(fixture("test_exe_linker_signed"), &options).unwrap();
    assert_eq!(
        verify(&signed).unwrap()[0].flags,
        CS_ADHOC | CS_LINKER_SIGNED
    );
    assert!(is_linker_signed(&signed));
}

#[test]
fn custom_entitlements_roundtrip() {
    let options = AdhocSignOptions::new("test.entitled")
        .with_entitlements(Entitlements::Custom(TEST_ENTITLEMENTS));
    let signed = adhoc_sign(fixture("test_exe_adhoc"), &options).unwrap();

    let infos = verify(&signed).unwrap();
    assert!(infos[0].has_entitlements);
    assert_eq!(infos[0].n_special_slots, 5);
    assert_eq!(
        extract_entitlements(&signed).as_deref(),
        Some(TEST_ENTITLEMENTS)
    );
}

#[test]
fn preserve_entitlements_keeps_existing_ones() {
    // First embed entitlements, then re-sign with `Preserve`.
    let entitled = adhoc_sign(
        fixture("test_exe_adhoc"),
        &AdhocSignOptions::new("first").with_entitlements(Entitlements::Custom(TEST_ENTITLEMENTS)),
    )
    .unwrap();

    let resigned = adhoc_sign(
        entitled,
        &AdhocSignOptions::new("second").with_entitlements(Entitlements::Preserve),
    )
    .unwrap();

    assert_eq!(verify(&resigned).unwrap()[0].identifier, "second");
    assert_eq!(
        extract_entitlements(&resigned).as_deref(),
        Some(TEST_ENTITLEMENTS)
    );
}

#[test]
fn preserve_entitlements_on_binary_without_them_is_none() {
    let signed = adhoc_sign(
        fixture("test_exe_adhoc"),
        &AdhocSignOptions::new("test").with_entitlements(Entitlements::Preserve),
    )
    .unwrap();
    assert!(!verify(&signed).unwrap()[0].has_entitlements);
}

#[test]
fn is_linker_signed_fixture() {
    assert!(is_linker_signed(&fixture("test_exe_linker_signed")));
    assert!(!is_linker_signed(&fixture("test_exe_adhoc")));
    assert!(!is_linker_signed(&fixture("test_exe_unsigned")));
    assert!(!is_linker_signed(b"not a binary"));
}

// ---------------------------------------------------------------------------
// Fat (universal) binaries.
// ---------------------------------------------------------------------------

#[test]
fn fat_binary_is_signed_per_slice() {
    let data = fixture("test_exe_fat");
    let options = AdhocSignOptions::new("fat.test");
    let signed = adhoc_sign(data, &options).unwrap();

    let infos = verify(&signed).unwrap();
    assert!(infos.len() >= 2, "expected at least two slices");
    for info in &infos {
        assert_eq!(info.identifier, "fat.test");
        assert_eq!(info.flags, CS_ADHOC);
    }
}

#[test]
fn fat_binary_streaming_is_rejected() {
    let data = fixture("test_exe_fat");
    let mut signer = StreamingSigner::new(Vec::new(), &AdhocSignOptions::new("fat.test")).unwrap();
    let err = signer.write_all(&data).unwrap_err();
    assert!(err.to_string().contains("streaming"), "{err}");
}

// ---------------------------------------------------------------------------
// Streaming signing must be byte-for-byte identical to in-memory signing,
// regardless of how the input is chunked.
// ---------------------------------------------------------------------------

#[rstest]
#[case::adhoc("test_exe_adhoc")]
#[case::linker_signed("test_exe_linker_signed")]
#[case::unsigned("test_exe_unsigned")]
#[case::bzip2("conda-repackaged/bzip2")]
#[case::openssl("conda-repackaged/openssl")]
#[case::python("conda-repackaged/python3.13")]
fn streaming_matches_in_memory(#[case] name: &str) {
    let data = fixture(name);
    let options = AdhocSignOptions::new("stream.test");
    let in_memory = adhoc_sign(data.clone(), &options).unwrap();
    verify(&in_memory).unwrap();

    // Chunk sizes chosen to hit page boundaries, header boundaries and
    // pathological single-byte writes.
    for chunk_size in [1usize, 7, 1000, 4095, 4096, 4097, 65536, data.len()] {
        let streamed = streaming_sign(&data, &options, chunk_size);
        assert_eq!(
            in_memory, streamed,
            "streaming output differs from in-memory output for {name} with chunk size {chunk_size}"
        );
    }
}

#[test]
fn streaming_with_custom_entitlements_matches_in_memory() {
    let data = fixture("test_exe_adhoc");
    let options = AdhocSignOptions::new("stream.entitled")
        .with_entitlements(Entitlements::Custom(TEST_ENTITLEMENTS));
    let in_memory = adhoc_sign(data.clone(), &options).unwrap();
    let streamed = streaming_sign(&data, &options, 8192);
    assert_eq!(in_memory, streamed);
    assert!(verify(&streamed).unwrap()[0].has_entitlements);
}

#[test]
fn streaming_rejects_preserve_entitlements() {
    let options = AdhocSignOptions::new("test").with_entitlements(Entitlements::Preserve);
    assert!(matches!(
        StreamingSigner::new(Vec::new(), &options),
        Err(SignError::CannotPreserveWhenStreaming)
    ));
}

#[test]
fn streaming_rejects_truncated_input() {
    let data = fixture("test_exe_adhoc");
    let options = AdhocSignOptions::new("test");

    // Cut off in the middle of the code pages.
    let mut signer = StreamingSigner::new(Vec::new(), &options).unwrap();
    signer.write_all(&data[..8192]).unwrap();
    assert!(matches!(
        signer.finish(),
        Err(SignError::TruncatedInput { .. })
    ));

    // Cut off in the middle of the header.
    let mut signer = StreamingSigner::new(Vec::new(), &options).unwrap();
    signer.write_all(&data[..16]).unwrap();
    assert!(matches!(
        signer.finish(),
        Err(SignError::TruncatedInput { .. })
    ));

    // Empty input.
    let signer = StreamingSigner::new(Vec::new(), &options).unwrap();
    assert!(matches!(signer.finish(), Err(SignError::NotMachO)));
}

// ---------------------------------------------------------------------------
// File-based signing.
// ---------------------------------------------------------------------------

#[rstest]
#[case::adhoc("test_exe_adhoc")]
#[case::unsigned("test_exe_unsigned")]
#[case::fat("test_exe_fat")]
#[case::python("conda-repackaged/python3.13")]
fn sign_file_matches_in_memory(#[case] name: &str) {
    let data = fixture(name);
    let options = AdhocSignOptions::new("file.test").with_entitlements(Entitlements::Preserve);
    let in_memory = adhoc_sign(data.clone(), &options).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("binary");
    std::fs::write(&path, &data).unwrap();
    adhoc_sign_file(&path, &options).unwrap();

    let on_disk = std::fs::read(&path).unwrap();
    assert_eq!(in_memory, on_disk);
    verify(&on_disk).unwrap();
}

#[cfg(unix)]
#[test]
fn sign_file_preserves_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("binary");
    std::fs::write(&path, fixture("test_exe_adhoc")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();

    adhoc_sign_file(&path, &AdhocSignOptions::new("test")).unwrap();

    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o755, "executable bit must survive signing");
}

#[test]
fn sign_file_rejects_non_macho() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("not-a-binary");
    std::fs::write(&path, b"#!/bin/sh\necho hello\n").unwrap();
    assert!(matches!(
        adhoc_sign_file(&path, &AdhocSignOptions::new("test")),
        Err(SignError::NotMachO)
    ));
    // The file must be left untouched.
    assert_eq!(std::fs::read(&path).unwrap(), b"#!/bin/sh\necho hello\n");
}

// ---------------------------------------------------------------------------
// Robustness: malformed input must error, never panic.
// ---------------------------------------------------------------------------

#[test]
fn malformed_input_errors_instead_of_panicking() {
    let options = AdhocSignOptions::new("test");

    // Truncations of a real binary at every interesting boundary.
    let data = fixture("test_exe_adhoc");
    for len in [0, 1, 3, 4, 8, 27, 28, 31, 32, 100, 4096] {
        let truncated = data[..len].to_vec();
        assert!(
            adhoc_sign(truncated, &options).is_err(),
            "truncation to {len} bytes must error"
        );
    }

    // Garbage with a valid magic.
    let mut garbage = vec![0u8; 1024];
    garbage[..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
    garbage[16..20].copy_from_slice(&1000u32.to_le_bytes()); // ncmds
    garbage[20..24].copy_from_slice(&u32::MAX.to_le_bytes()); // sizeofcmds
    assert!(adhoc_sign(garbage, &options).is_err());

    // Random bytes fed to the verifier.
    assert!(verify(b"\xcf\xfa\xed\xfe garbage").is_err());
    assert!(verify(&[]).is_err());
}

#[test]
fn unsigned_binary_gains_a_signature() {
    let data = fixture("test_exe_unsigned");
    let signed = adhoc_sign(data.clone(), &AdhocSignOptions::new("fresh")).unwrap();
    assert!(signed.len() > data.len());
    let infos = verify(&signed).unwrap();
    assert_eq!(infos[0].identifier, "fresh");
}
