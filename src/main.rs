//! src/main.rs
//!
//! The host-side `mkimage` utility, and the crate that links the kernel.
//!
//! The bare-metal side of this binary is the library's: `arch::entry` holds
//! the entry symbols the boot assembly calls, and everything after them.  What
//! is left here is the host half — the `mkimage` command that writes a demo
//! disk image — and the two `extern crate` lines that make a bare-metal build
//! link the kernel's objects in.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

extern crate alloc;
extern crate protofire;

#[cfg(not(target_os = "none"))]
use std::env;
#[cfg(not(target_os = "none"))]
use std::fs;
#[cfg(not(target_os = "none"))]
use std::path::Path;
#[cfg(not(target_os = "none"))]
use std::process;

#[cfg(not(target_os = "none"))]
const KERNEL_NAME: &str = env!("CARGO_PKG_NAME");
#[cfg(not(target_os = "none"))]
const KERNEL_VERSION: &str = env!("CARGO_PKG_VERSION");
#[cfg(not(target_os = "none"))]
const BUILD_PROFILE: &str = if cfg!(debug_assertions) {
    "debug"
} else {
    "release"
};

#[cfg(not(target_os = "none"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);

    match args.next().as_deref() {
        Some("mkimage") => {
            // `mkimage [gpt] [path]`: the table is the argument that matters,
            // because both images carry the same zones
            // ([RFC 0018](../../docs/rfcs/0018-read-a-disk-whose-table-is-gpt.md)).
            let first = args.next();
            let (table, output) = match first.as_deref() {
                Some("gpt") => (
                    DemoDiskTable::Gpt,
                    args.next()
                        .unwrap_or_else(|| "target/protofire-demo-gpt.img".to_string()),
                ),
                Some(path) => (DemoDiskTable::Mbr, path.to_string()),
                None => (
                    DemoDiskTable::Mbr,
                    "target/protofire-demo-disk.img".to_string(),
                ),
            };
            if args.next().is_some() {
                print_host_usage_and_exit(2);
            }

            write_demo_disk_image(Path::new(&output), table)?;
        }
        Some("install") => {
            // `install [--new-table] <disk-image>`: put this kernel's zones
            // onto a disk a machine already has, adding the zones to the
            // disk's own GPT rather than building an image.  `--new-table`
            // is the opt-in for a disk that has no table at all — the flag is
            // the decision, because writing one is partitioning.  See
            // `protofire::fs::install`.
            let first = args.next();
            let (new_table, path) = match first.as_deref() {
                Some("--new-table") => (true, args.next()),
                _ => (false, first),
            };
            let Some(path) = path else {
                print_host_usage_and_exit(2);
            };
            if args.next().is_some() {
                print_host_usage_and_exit(2);
            }

            install_zones_onto_disk(Path::new(&path), new_table)?;
        }
        Some("sign-release") => {
            let artifact = args.next().unwrap_or_else(|| {
                print_host_usage_and_exit(2);
            });
            let key_id = args.next().unwrap_or_else(|| {
                print_host_usage_and_exit(2);
            });
            let output_dir = args.next();
            if args.next().is_some() {
                print_host_usage_and_exit(2);
            }

            sign_release_artifact(Path::new(&artifact), &key_id, output_dir.as_deref())?;
        }
        Some("verify-signature") => {
            let artifact = args.next().unwrap_or_else(|| {
                print_host_usage_and_exit(2);
            });
            let signature = args.next().unwrap_or_else(|| {
                print_host_usage_and_exit(2);
            });
            let public_key = args.next().unwrap_or_else(|| {
                print_host_usage_and_exit(2);
            });
            if args.next().is_some() {
                print_host_usage_and_exit(2);
            }

            verify_artifact_signature(
                Path::new(&artifact),
                Path::new(&signature),
                Path::new(&public_key),
            )?;
        }
        Some(_) => {
            print_host_usage_and_exit(2);
        }
        None => {
            println!(
                "{} v{} host stub [{}]",
                KERNEL_NAME, KERNEL_VERSION, BUILD_PROFILE
            );
            println!("Build the bare-metal kernel with `make build`.");
            println!("Host commands:");
            println!(
                "  mkimage [gpt] [path]  Build the ATA demo disk image (MBR by default, GPT on request)."
            );
            println!("  install [--new-table] <disk>  Install this kernel's zones onto a disk.  A");
            println!(
                "    disk that already has a GPT keeps every partition it carried; --new-table"
            );
            println!("    writes a fresh GPT first, for a disk that has no table at all.");
            println!(
                "  sign-release <artifact> <key-id> [dir]  Sign an artifact with a fresh one-time key."
            );
            println!(
                "  verify-signature <artifact> <sig> <key>  Check a signature against a key record."
            );
        }
    }

    Ok(())
}

/// Which partition table a demo image the host writes carries.
#[cfg(not(target_os = "none"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DemoDiskTable {
    Mbr,
    Gpt,
}

#[cfg(not(target_os = "none"))]
fn write_demo_disk_image(
    path: &Path,
    table: DemoDiskTable,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let image = match table {
        DemoDiskTable::Mbr => protofire::fs::build_demo_disk_image(),
        DemoDiskTable::Gpt => protofire::fs::build_demo_gpt_disk_image(),
    };
    fs::write(path, &image)?;
    println!("wrote {} bytes to {}", image.len(), path.display());
    Ok(())
}

/// Install this kernel's zones onto the GPT disk image at `path`.
///
/// The disk is read whole, the install runs in memory, and the result is
/// written back — which is what makes the operation testable and what makes
/// a failure leave the disk exactly as it was.  A real installer would write
/// through the device; this is the same operation with the device being a
/// file.
///
/// `new_table` is the caller's opt-in for a disk that carries no table: with
/// it the install writes a fresh GPT, without it such a disk is refused.
#[cfg(not(target_os = "none"))]
fn install_zones_onto_disk(path: &Path, new_table: bool) -> Result<(), Box<dyn std::error::Error>> {
    let mut disk = fs::read(path)?;
    if disk.len() % 512 != 0 {
        return Err(format!(
            "{} is {} bytes, not a whole number of 512-byte blocks",
            path.display(),
            disk.len()
        )
        .into());
    }

    let outcome = if new_table {
        protofire::fs::install::install_zones_into_blank_disk_image(&mut disk)
    } else {
        protofire::fs::install::install_zones_into_disk_image(&mut disk)
    };
    let report = outcome.map_err(|error| format!("{}: {}", path.display(), error.as_str()))?;

    fs::write(path, &disk)?;

    println!(
        "installed onto {}{}",
        path.display(),
        if report.created_table {
            " (a fresh GPT was written)"
        } else {
            ""
        }
    );
    for zone in &report.zones {
        println!(
            "  {} zone: blocks {}..={} ({} blocks, {})",
            zone.zone.zone_root(),
            zone.first_block,
            zone.last_block,
            zone.last_block - zone.first_block + 1,
            if zone.reused { "reused" } else { "placed" }
        );
    }
    println!(
        "  {} entry(ies) in the table after the install",
        report.entries.len()
    );
    Ok(())
}

/// Sign one release artifact, with a key that has never signed anything else.
///
/// The key is generated here, once, because that is the only way to be sure it
/// is used once: a Lamport key that signs twice reveals both preimages of every
/// bit the two digests disagree on, which is enough to forge a third
/// signature.  The public half is written beside the signature, because a
/// verifier has no other way to get it.
#[cfg(not(target_os = "none"))]
fn sign_release_artifact(
    artifact_path: &Path,
    key_id: &str,
    output_dir: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    use protofire::util::sign_tool;

    let artifact = fs::read(artifact_path)?;
    let directory = match output_dir {
        Some(dir) => std::path::PathBuf::from(dir),
        None => artifact_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| std::path::PathBuf::from(".")),
    };
    fs::create_dir_all(&directory)?;

    let file_name = artifact_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("the artifact has no file name to name its signature after")?;
    let signature_path = directory.join(format!("{file_name}.sig"));
    let public_key_path = directory.join(format!("{key_id}.public.toml"));

    // One artifact, one key: signing the same artifact again needs a second key,
    // and a file that is already there is either that first signature or
    // somebody else's.  Overwriting either would be the mistake this scheme
    // cannot afford.
    for path in [&signature_path, &public_key_path] {
        if path.exists() {
            return Err(format!(
                "{} exists; a key signs one artifact, so give this one a new key id",
                path.display()
            )
            .into());
        }
    }

    let key = sign_tool::generate_key_pair(key_id, sign_tool::fill_from_urandom)
        .map_err(|error| format!("cannot generate a key: {error}"))?;
    let signed = sign_tool::sign_artifact(&key, &artifact)
        .map_err(|error| format!("cannot sign {}: {error}", artifact_path.display()))?;

    fs::write(&signature_path, format!("{}\n", signed.signature))?;
    fs::write(&public_key_path, &signed.public_key_record)?;

    println!(
        "signed {} ({} bytes) with one-time key {}",
        artifact_path.display(),
        artifact.len(),
        key.key_id
    );
    println!("  signature:  {}", signature_path.display());
    println!("  public key: {}", public_key_path.display());
    println!(
        "The key is spent: it must not sign anything else, and the key record is \
         what a verifier needs beside the signature."
    );
    Ok(())
}

/// Check a signature against the key record that came with it.
#[cfg(not(target_os = "none"))]
fn verify_artifact_signature(
    artifact_path: &Path,
    signature_path: &Path,
    public_key_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    use protofire::util::sign_tool;

    let artifact = fs::read(artifact_path)?;
    let signature = fs::read_to_string(signature_path)?;
    let public_key_record = fs::read_to_string(public_key_path)?;

    match sign_tool::verify_artifact(&artifact, &signature, &public_key_record) {
        Ok(()) => {
            println!(
                "ok: {} matches the signature under {}",
                artifact_path.display(),
                public_key_path.display()
            );
            Ok(())
        }
        Err(error) => Err(format!(
            "{} does not match {}: {error}",
            artifact_path.display(),
            signature_path.display()
        )
        .into()),
    }
}

#[cfg(not(target_os = "none"))]
fn print_host_usage_and_exit(code: i32) -> ! {
    eprintln!("usage: cargo run -- mkimage [output]");
    eprintln!("       cargo run -- sign-release <artifact> <key-id> [dir]");
    eprintln!("       cargo run -- verify-signature <artifact> <sig> <public-key>");
    process::exit(code);
}
