# arwen-codesign

Fast, pure-Rust ad-hoc code signing for Mach-O binaries — the equivalent of
`codesign --force --sign -` — usable from any host platform.

This crate was originally part of [goblin-ext](https://github.com/wolfv/goblin-ext) and has been migrated into the arwen workspace.

## Features

- Ad-hoc signing of thin **and fat (universal)** Mach-O binaries
- **Streaming signer** (`StreamingSigner`): sign a binary in a single pass
  while it is being written — ideal for installer pipelines that transform
  and re-sign thousands of binaries (~1.3 GB/s single-threaded, hundreds of
  times faster than spawning `/usr/bin/codesign`)
- **Signature verification** (`verify`): re-check every page hash and
  structural invariant on any host platform, no macOS required
- Entitlements preservation (`--preserve-metadata=entitlements`) or custom
  injection
- Hardened runtime (`CS_RUNTIME`) and linker-signed (`CS_LINKER_SIGNED`) flags
- Signing unsigned binaries (inserts `LC_CODE_SIGNATURE` into header padding)
- Atomic in-place file signing that preserves file permissions
- Both 32-bit and 64-bit binaries; bounds-checked parsing that never panics
  on malformed input
- Optional `parallel` feature (rayon page hashing) and `asm` feature
  (assembly SHA-256)

## Usage

### Basic Ad-hoc Signing

```rust,ignore
use arwen_codesign::{adhoc_sign, AdhocSignOptions};

let signed = adhoc_sign(data, &AdhocSignOptions::new("com.example.myapp"))?;
```

### With Hardened Runtime and Preserved Entitlements

```rust,ignore
use arwen_codesign::{adhoc_sign, AdhocSignOptions, Entitlements};

let options = AdhocSignOptions::new("com.example.myapp")
    .with_hardened_runtime()
    .with_entitlements(Entitlements::Preserve);
let signed = adhoc_sign(data, &options)?;
```

### File-based API (streaming, atomic replace)

```rust,ignore
use arwen_codesign::{adhoc_sign_file, AdhocSignOptions, Entitlements};
use std::path::Path;

let options = AdhocSignOptions::new("com.example.myapp")
    .with_entitlements(Entitlements::Preserve);
adhoc_sign_file(Path::new("/path/to/binary"), &options)?;
```

### Single-pass transform + sign pipelines

```rust,ignore
use std::io::Write;
use arwen_codesign::{AdhocSignOptions, StreamingSigner};

let output = std::fs::File::create("signed_binary")?;
let mut signer = StreamingSigner::new(std::io::BufWriter::new(output),
                                      &AdhocSignOptions::new("my_binary"))?;
// Write the (possibly transformed) binary through the signer...
signer.write_all(&patched_bytes)?;
// ...and finish to append the signature.
signer.finish()?.flush()?;
```

### Verification

```rust,ignore
let infos = arwen_codesign::verify(&signed_bytes)?;
assert_eq!(infos[0].identifier, "com.example.myapp");
```

## Testing

Rust integration tests live in `tests/codesign.rs` and validate the verifier
against binaries signed by Apple's real `codesign` tool, then validate all
signing paths (in-memory, streaming, file-based) against the verifier — on
any host platform.

Python tests are available in the workspace `tests/python_integration/codesign/`:

- `test_codesign.py` - Comprehensive tests comparing against Apple's codesign tool

Test assets are located in `tests/data/macho/codesign/` and include various signed/unsigned Mach-O binaries:
- `test_exe_adhoc` - Ad-hoc signed executable
- `test_exe_fat` - Universal/fat binary
- `test_exe_hardened` - Executable with hardened runtime
- `test_exe_linker_signed` - Linker-signed executable
- `test_exe_unsigned` - Unsigned executable
- `conda-repackaged/*` - Real-world binaries re-signed by codesign after prefix patching

## License

MIT
