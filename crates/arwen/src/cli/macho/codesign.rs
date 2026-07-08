use arwen_codesign::{adhoc_sign_file, AdhocSignOptions, Entitlements, SignError};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(about = "Ad-hoc code sign a Mach-O binary")]
pub struct Args {
    /// Identifier for the signature (e.g., com.example.myapp)
    #[arg(short, long)]
    pub identifier: String,

    /// Path to the binary file to sign
    pub file: PathBuf,

    /// Enable hardened runtime (equivalent to codesign --options runtime)
    #[arg(long)]
    pub hardened_runtime: bool,

    /// Preserve existing entitlements from the binary's current signature
    #[arg(long)]
    pub preserve_entitlements: bool,

    /// Set linker-signed flag (use when re-signing linker-signed binaries)
    #[arg(long)]
    pub linker_signed: bool,
}

pub fn execute(args: Args) -> Result<(), SignError> {
    // Build signing options
    let mut options = AdhocSignOptions::new(&args.identifier);

    if args.hardened_runtime {
        options = options.with_hardened_runtime();
    }

    if args.linker_signed {
        options = options.with_linker_signed();
    }

    if args.preserve_entitlements {
        options = options.with_entitlements(Entitlements::Preserve);
    }

    // Sign the file in place (streaming, atomic replace).
    adhoc_sign_file(&args.file, &options)?;

    println!("Successfully signed: {}", args.file.display());

    Ok(())
}
