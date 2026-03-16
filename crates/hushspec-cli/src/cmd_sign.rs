use colored::Colorize;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct SignArgs {
    /// Policy file to sign
    #[arg(required = true)]
    policy: PathBuf,

    /// Path to the Ed25519 private key file
    #[arg(short, long)]
    key: PathBuf,

    /// Key identifier (defaults to a truncated hash of the public key)
    #[arg(long)]
    key_id: Option<String>,

    /// Human-readable signer identity (e.g. email)
    #[arg(long)]
    signer: Option<String>,

    /// Output path for the .sig file (defaults to <POLICY>.sig)
    #[arg(short, long)]
    output: Option<PathBuf>,
}

pub fn run(args: SignArgs) -> i32 {
    // Read the policy file (raw bytes for signing)
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

    // Read the private key
    let key_content = match std::fs::read_to_string(&args.key) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "{} Failed to read key file {}: {e}",
                "ERROR".red(),
                args.key.display()
            );
            return 1;
        }
    };

    let signing_key = match hushspec::signing::parse_private_key_pem(&key_content) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("{} Invalid private key: {e}", "ERROR".red());
            return 1;
        }
    };

    // Derive key_id from public key if not provided
    let key_id = args.key_id.unwrap_or_else(|| {
        let vk = signing_key.verifying_key();
        let encoded = hushspec::signing::encode_verifying_key(&vk);
        // Use first 16 chars of the base64-encoded public key as identifier
        format!("ed25519:{}", &encoded[..16])
    });

    let signature =
        hushspec::signing::sign_policy(&content, &signing_key, &key_id, args.signer.as_deref());

    // Determine output path
    let output_path = args.output.unwrap_or_else(|| {
        let mut p = args.policy.clone().into_os_string();
        p.push(".sig");
        PathBuf::from(p)
    });

    match hushspec::signing::save_signature(&signature, &output_path) {
        Ok(()) => {
            println!(
                "  {} {} (key: {})",
                "Signed".green().bold(),
                output_path.display(),
                key_id,
            );
            println!("  {} {}", "Hash".dimmed(), signature.content_hash,);
            0
        }
        Err(e) => {
            eprintln!("{} Failed to write signature file: {e}", "ERROR".red());
            1
        }
    }
}
