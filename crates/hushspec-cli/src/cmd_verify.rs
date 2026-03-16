use colored::Colorize;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct VerifyArgs {
    /// Policy file to verify
    #[arg(required = true)]
    policy: PathBuf,

    /// Path to the detached .sig file (defaults to <POLICY>.sig)
    #[arg(short, long)]
    sig: Option<PathBuf>,

    /// Path to the Ed25519 public key file
    #[arg(short, long)]
    key: PathBuf,
}

pub fn run(args: VerifyArgs) -> i32 {
    // Read the policy file (raw bytes)
    let content = match std::fs::read(&args.policy) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{} Failed to read policy file {}: {e}",
                "ERROR".red(),
                args.policy.display()
            );
            return 1;
        }
    };

    // Determine signature file path
    let sig_path = args.sig.unwrap_or_else(|| {
        let mut p = args.policy.clone().into_os_string();
        p.push(".sig");
        PathBuf::from(p)
    });

    // Load the signature
    let signature = match hushspec::signing::load_signature(&sig_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "{} Failed to load signature from {}: {e}",
                "ERROR".red(),
                sig_path.display()
            );
            return 1;
        }
    };

    // Read the public key
    let key_content = match std::fs::read_to_string(&args.key) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{} Failed to read public key file {}: {e}",
                "ERROR".red(),
                args.key.display()
            );
            return 1;
        }
    };

    let verifying_key = match hushspec::signing::parse_public_key_pem(&key_content) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("{} Invalid public key: {e}", "ERROR".red());
            return 1;
        }
    };

    // Verify
    match hushspec::signing::verify_policy(&content, &signature, &verifying_key) {
        hushspec::signing::VerificationOutcome::Valid {
            key_id,
            signed_at,
            signer,
        } => {
            println!("{} Signature is valid", "\u{2713}".green());
            println!("  {} {}", "Key ID:".dimmed(), key_id);
            println!("  {} {}", "Signed at:".dimmed(), signed_at);
            if let Some(signer) = signer {
                println!("  {} {}", "Signer:".dimmed(), signer);
            }
            println!("  {} {}", "Content hash:".dimmed(), signature.content_hash);
            0
        }
        hushspec::signing::VerificationOutcome::Invalid { reason } => {
            eprintln!(
                "{} Signature verification failed: {reason}",
                "\u{2717}".red()
            );
            1
        }
        hushspec::signing::VerificationOutcome::NoSignature => {
            eprintln!("{} No signature found", "\u{2717}".red());
            1
        }
    }
}
