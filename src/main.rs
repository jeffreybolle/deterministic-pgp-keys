use crate::generate::generate_keys;
use bip39::{Language, Mnemonic};
use chrono::{NaiveDate, TimeZone, Utc};
use clap::CommandFactory;
use clap::Parser;
use rand::{thread_rng, RngCore};
use std::fs::File;
use std::io::Write;
use std::process::exit;
use std::str::FromStr;

mod generate;

#[macro_use]
extern crate nom;
#[macro_use]
extern crate num_derive;
#[macro_use]
extern crate generic_array;
#[macro_use]
extern crate log;
#[macro_use]
extern crate derive_builder;
#[macro_use]
extern crate bitfield;
#[macro_use]
extern crate smallvec;

mod pgp;

/// Program to create deterministic PGP keys
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long, help("Generate a new random seed phrase"))]
    generate: bool,

    #[clap(long, help("Provide your full name"))]
    name: String,

    #[clap(
        long,
        required(true),
        help("Provide your email address (this option can be repeated)")
    )]
    email: Vec<String>,

    #[clap(long, help("Provide the creation date for the PGP key"))]
    date: NaiveDate,

    #[clap(long, help("Path to write private key file"))]
    private_key: Option<String>,

    #[clap(long, help("Path to write public key file"))]
    public_key: Option<String>,

    #[clap(long, help("Print the seed phrase without numbers"))]
    plain_seed_phrase: bool,

    #[clap(long, help("Passphrase to encrypt the private key"))]
    passphrase: bool,
}

fn pad(s: &str, length: usize) -> String {
    let mut s = s.to_string();
    while s.len() < length {
        s.push(' ');
    }
    s
}

fn read_seed_phrase() -> Result<Mnemonic, anyhow::Error> {
    let mut words = String::new();
    let mut stdout = std::io::stdout();
    write!(stdout, "Seed Phrase: ")?;
    stdout.flush()?;
    std::io::stdin().read_line(&mut words)?;
    Ok(Mnemonic::from_str(words.trim())?)
}

fn generate_seed_phrase(args: &Args) -> Result<Mnemonic, anyhow::Error> {
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

    println!();
}

fn read_passphrase() -> Result<String, anyhow::Error> {
    let passphrase = rpassword::prompt_password("Passphrase: ")?;
    Ok(passphrase.trim().to_string())
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
        generate_seed_phrase(&args)?
    } else {
        read_seed_phrase()?
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
        Utc.from_utc_datetime(&args.date.and_hms_opt(0, 0, 0).unwrap()),
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
