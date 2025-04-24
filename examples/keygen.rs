use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

use base64::prelude::*;
use clap::Parser;
use plonky2_rsa::rsa::{RSAKeypair, RSAPubkey};
use serde::{Deserialize, Serialize};

#[derive(Parser, Debug)]
#[command(author, version, about = "Generate RSA keypairs")]
struct Args {
    /// Output file path for the keypair
    #[arg(short, long, default_value = "keypair.json")]
    output: PathBuf,

    /// Only save public key
    #[arg(short, long)]
    pub_only: bool,
}

#[derive(Serialize, Deserialize)]
struct KeypairJson {
    public_key: String,
    private_key: Option<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!("Generating RSA keypair...");
    let keypair = RSAKeypair::new();
    let pubkey = keypair.get_pubkey();

    println!("RSA keypair generated successfully");

    let json_data = if args.pub_only {
        KeypairJson {
            public_key: pubkey.base64(),
            private_key: None,
        }
    } else {
        KeypairJson {
            public_key: pubkey.base64(),
            private_key: Some(BASE64_STANDARD.encode(keypair.sk.to_bytes_le())),
        }
    };

    let serialized = serde_json::to_string_pretty(&json_data)?;

    println!("Saving to {}...", args.output.display());
    let mut file = File::create(args.output)?;
    file.write_all(serialized.as_bytes())?;

    println!("Done!");
    Ok(())
}
