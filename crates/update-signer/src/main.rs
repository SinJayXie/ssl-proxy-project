//! 更新包签名工具（仅发布流程使用，不随产品分发）。
//!
//! ```text
//! update-signer keygen <private-key.der> <public-key.hex>
//! update-signer sign   <private-key.der> <file>
//! update-signer verify <public-key.hex> <file> <signature-hex>
//! ```
//!
//! 客户端内置公钥（`crates/gui/assets/update_pubkey.hex`），下载安装包后用
//! Ed25519 校验签名；私钥只保留在发布机器上（默认 `.secrets/`，已 gitignore）。

use std::fs;
use std::path::Path;
use std::process::ExitCode;

use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [cmd, private, public] if cmd == "keygen" => keygen(private, public),
        [cmd, private, file] if cmd == "sign" => sign(private, file),
        [cmd, public, file, signature] if cmd == "verify" => verify(public, file, signature),
        _ => {
            eprintln!(
                "usage:\n  update-signer keygen <private-key.der> <public-key.hex>\n  update-signer sign <private-key.der> <file>\n  update-signer verify <public-key.hex> <file> <signature-hex>"
            );
            return ExitCode::from(2);
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn keygen(private_path: &str, public_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
        .map_err(|_| "failed to generate Ed25519 key pair")?;
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
        .map_err(|_| "failed to load generated Ed25519 key pair")?;

    for path in [private_path, public_path] {
        if let Some(dir) = Path::new(path).parent() {
            fs::create_dir_all(dir)?;
        }
    }
    fs::write(private_path, pkcs8.as_ref())?;
    let public_hex = hex(key_pair.public_key().as_ref());
    fs::write(public_path, format!("{public_hex}\n"))?;

    println!("private key: {private_path}");
    println!("public key:  {public_path}");
    println!("public hex:  {public_hex}");
    Ok(())
}

fn sign(private_path: &str, file: &str) -> Result<(), Box<dyn std::error::Error>> {
    let pkcs8 = fs::read(private_path)?;
    let key_pair = Ed25519KeyPair::from_pkcs8(&pkcs8)
        .map_err(|_| "invalid Ed25519 private key (PKCS#8 DER expected)")?;
    let data = fs::read(file)?;
    println!("{}", hex(key_pair.sign(&data).as_ref()));
    Ok(())
}

/// 发布前自检：用公钥验证签名（与客户端校验逻辑一致）
fn verify(
    public_hex: &str,
    file: &str,
    signature_hex: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let public_key = unhex(public_hex.trim())?;
    let signature = unhex(signature_hex.trim())?;
    let data = fs::read(file)?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key)
        .verify(&data, &signature)
        .map_err(|_| "signature mismatch")?;
    println!("signature ok: {file}");
    Ok(())
}

fn unhex(value: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if value.len() % 2 != 0 {
        return Err("hex string has odd length".into());
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16).ok_or("invalid hex digit")? as u8;
        let lo = (pair[1] as char).to_digit(16).ok_or("invalid hex digit")? as u8;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;

    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}
