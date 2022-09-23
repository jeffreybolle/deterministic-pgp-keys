use bip39::{Language, Mnemonic};
use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use clap::CommandFactory;
use clap::Parser;
use pgp::composed::{key::SecretKeyParamsBuilder, KeyType};
use pgp::crypto::{hash::HashAlgorithm, sym::SymmetricKeyAlgorithm};
use pgp::types::CompressionAlgorithm;
use pgp::{SignedSecretKey, SubkeyParamsBuilder};
use rand::{thread_rng, RngCore, SeedableRng};
use sha2::{Digest, Sha256};
use smallvec::*;
use std::fs::File;
use std::io::Write;
use std::process::exit;
use std::str::FromStr;

/// Program to create deterministic PGP keys
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    generate: bool,

    #[clap(long)]
    name: String,

    #[clap(long)]
    email: String,

    #[clap(long)]
    date: NaiveDate,

    #[clap(long)]
    private_key: Option<String>,

    #[clap(long)]
    public_key: Option<String>,

    #[clap(long)]
    plain_seed_phrase: bool,

    #[clap(long)]
    passphrase: bool,
}

fn pad(s: &str, length: usize) -> String {
    let mut s = s.to_string();
    while s.len() < length {
        s.push(' ');
    }
    s
}

fn read_mnemonic() -> Result<Mnemonic, anyhow::Error> {
    let mut words = String::new();
    let mut stdout = std::io::stdout();
    write!(stdout, "Seed Phrase: ")?;
    stdout.flush()?;
    std::io::stdin().read_line(&mut words)?;
    Ok(Mnemonic::from_str(words.trim())?)
}

fn generate_mnemonic(args: &Args) -> Result<Mnemonic, anyhow::Error> {
    let mut rng = thread_rng();
    let mut entropy = [0u8; 16];
    rng.fill_bytes(&mut entropy);
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)?;
    print_mnemonic(&mnemonic, args);
    Ok(mnemonic)
}

fn print_mnemonic(mnemonic: &Mnemonic, args: &Args) {
    let words: Vec<_> = mnemonic.word_iter().map(str::to_string).collect();

    println!();
    println!("Seed Phrase:");
    println!();

    if !args.plain_seed_phrase {
        let length = mnemonic.word_iter().map(str::len).max().unwrap();
        for i in 0..6 {
            println!(
                "  {: >2}: {}  {: >2}: {}",
                i + 1,
                pad(&words[i], length),
                i + 7,
                words[i + 6]
            );
        }
    } else {
        println!("  {}", words.join(" "));
    }
}

fn read_passphrase() -> Result<String, anyhow::Error> {
    let mut passphrase = String::new();
    let mut stdout = std::io::stdout();
    write!(stdout, "Passphrase: ")?;
    stdout.flush()?;
    std::io::stdin().read_line(&mut passphrase)?;
    Ok(passphrase.trim().to_string())
}

fn generate_keys(
    mnemonic: Mnemonic,
    name: String,
    email: String,
    created_time: DateTime<Utc>,
    passphrase: Option<String>,
) -> Result<SignedSecretKey, anyhow::Error> {
    let master_seed = mnemonic.to_seed("");
    let passwd_fn = {
        let passphrase = match passphrase {
            Some(ref passphrase) => passphrase.clone(),
            None => String::new(),
        };
        move || passphrase.clone()
    };

    let mut key_material = Vec::new();

    for index in 1..=4 {
        let mut rng = rand::rngs::StdRng::from_seed(derive_rng_seed(&master_seed, index));
        key_material.push(Some(
            KeyType::Rsa(4096).generate_with_rng(&mut rng, passphrase.clone())?,
        ));
    }

    let secret_key_params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Rsa(4096))
        .can_create_certificates(true)
        .can_sign(false)
        .can_encrypt(false)
        .primary_user_id(format!("{} <{}>", name, email))
        .preferred_symmetric_algorithms(smallvec![SymmetricKeyAlgorithm::AES256,])
        .preferred_hash_algorithms(smallvec![
            HashAlgorithm::SHA2_512,
            HashAlgorithm::SHA2_384,
            HashAlgorithm::SHA2_256,
            HashAlgorithm::SHA2_224,
        ])
        .preferred_compression_algorithms(smallvec![CompressionAlgorithm::ZLIB,])
        .created_at(created_time)
        .key_material(key_material[0].take())
        .passphrase(passphrase.clone())
        .subkeys(vec![
            SubkeyParamsBuilder::default()
                .can_create_certificates(false)
                .can_sign(true)
                .can_encrypt(false)
                .can_authenticate(false)
                .key_type(KeyType::Rsa(4096))
                .created_at(created_time.clone())
                .key_material(key_material[1].take())
                .passphrase(passphrase.clone())
                .build()
                .map_err(|err| anyhow::Error::msg(err))?,
            SubkeyParamsBuilder::default()
                .can_create_certificates(false)
                .can_sign(false)
                .can_encrypt(true)
                .can_authenticate(false)
                .key_type(KeyType::Rsa(4096))
                .created_at(created_time.clone())
                .key_material(key_material[2].take())
                .passphrase(passphrase.clone())
                .build()
                .map_err(|err| anyhow::Error::msg(err))?,
            SubkeyParamsBuilder::default()
                .can_create_certificates(false)
                .can_sign(false)
                .can_encrypt(false)
                .can_authenticate(true)
                .key_type(KeyType::Rsa(4096))
                .created_at(created_time.clone())
                .key_material(key_material[3].take())
                .passphrase(passphrase)
                .build()
                .map_err(|err| anyhow::Error::msg(err))?,
        ])
        .build()
        .map_err(|err| anyhow::Error::msg(err))?;

    let mut rng = rand::rngs::StdRng::from_seed(derive_rng_seed(&master_seed, 5));
    let secret_key = secret_key_params.generate_with_rng(&mut rng)?;
    let signed_secret_key = secret_key.sign(passwd_fn)?;

    Ok(signed_secret_key)
}

fn derive_rng_seed(master_seed: &[u8; 64], index: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"DERIVE");
    hasher.update(&master_seed);
    hasher.update(format!("/{}", index).as_bytes());
    let digest = hasher.finalize();

    let mut seed = [0u8; 32];
    seed[..32].copy_from_slice(&digest[..32]);
    seed
}

fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();

    if args.private_key.is_none() && args.public_key.is_none() {
        let mut cmd = Args::command();
        cmd.print_help()?;
        println!();
        println!("Please specify either --private-key, --public-key or both.");
        exit(1);
    }

    let mnemonic = if args.generate {
        generate_mnemonic(&args)?
    } else {
        read_mnemonic()?
    };

    let passphrase = if args.passphrase {
        Some(read_passphrase()?)
    } else {
        None
    };

    println!();

    let secret_key = generate_keys(
        mnemonic,
        args.name,
        args.email,
        Utc.from_utc_datetime(&args.date.and_hms(0, 0, 0)),
        passphrase,
    )?;

    let public_key = secret_key.signed_public_key()?;

    if let Some(private_key_file) = args.private_key {
        let mut file = File::create(private_key_file.clone())?;
        secret_key.to_armored_writer(&mut file, None)?;
        println!("written: {}", private_key_file);
    }

    if let Some(public_key_file) = args.public_key {
        let mut file = File::create(public_key_file.clone())?;
        public_key.to_armored_writer(&mut file, None)?;
        println!("written: {}", public_key_file);
    }

    Ok(())
}
