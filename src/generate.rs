use crate::pgp::composed::{key::SecretKeyParamsBuilder, KeyType};
use crate::pgp::crypto::{hash::HashAlgorithm, sym::SymmetricKeyAlgorithm};
use crate::pgp::types::CompressionAlgorithm;
use crate::pgp::{SignedSecretKey, SubkeyParamsBuilder};
use bip39::Mnemonic;
use chrono::{DateTime, Utc};
use rand::{CryptoRng, Rng, SeedableRng};
use sha2::{Digest, Sha256};
use smallvec::*;

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

fn new_rng(seed: [u8; 32]) -> impl Rng + CryptoRng {
    rand_chacha::ChaCha20Rng::from_seed(seed)
}

pub fn generate_keys(
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
        let mut rng = new_rng(derive_rng_seed(&master_seed, index));
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
                .created_at(created_time)
                .key_material(key_material[1].take())
                .passphrase(passphrase.clone())
                .build()
                .map_err(anyhow::Error::msg)?,
            SubkeyParamsBuilder::default()
                .can_create_certificates(false)
                .can_sign(false)
                .can_encrypt(true)
                .can_authenticate(false)
                .key_type(KeyType::Rsa(4096))
                .created_at(created_time)
                .key_material(key_material[2].take())
                .passphrase(passphrase.clone())
                .build()
                .map_err(anyhow::Error::msg)?,
            SubkeyParamsBuilder::default()
                .can_create_certificates(false)
                .can_sign(false)
                .can_encrypt(false)
                .can_authenticate(true)
                .key_type(KeyType::Rsa(4096))
                .created_at(created_time)
                .key_material(key_material[3].take())
                .passphrase(passphrase)
                .build()
                .map_err(anyhow::Error::msg)?,
        ])
        .build()
        .map_err(anyhow::Error::msg)?;

    let mut rng = new_rng(derive_rng_seed(&master_seed, 5));
    let secret_key = secret_key_params.generate_with_rng(&mut rng)?;
    let signed_secret_key = secret_key.sign(passwd_fn, created_time)?;

    Ok(signed_secret_key)
}

#[cfg(test)]
mod tests {
    use crate::generate_keys;
    use bip39::Mnemonic;
    use chrono::{NaiveDate, TimeZone, Utc};
    use digest::Digest;
    use sha2::Sha256;
    use std::str::FromStr;

    #[test]
    fn generation_is_stable() {
        let mnemonic = Mnemonic::from_str(
            "design car dutch struggle hello pluck bubble hospital muffin earn half best",
        )
        .unwrap();

        let secret_key = generate_keys(
            mnemonic,
            "Jeffrey Bolle".to_string(),
            "jeffreybolle@gmail.com".to_string(),
            Utc.from_utc_datetime(&NaiveDate::from_ymd(2022, 9, 21).and_hms(0, 0, 0)),
            None,
        )
        .unwrap();
        let public_key = secret_key.signed_public_key().unwrap();

        let mut secret_key_bytes = Vec::<u8>::new();
        secret_key
            .to_armored_writer(&mut secret_key_bytes, None)
            .unwrap();

        let mut hasher = Sha256::new();
        hasher.update(&secret_key_bytes);
        assert_eq!(
            "64c44c971ae50ddd3a30c516e5249e736e883b1d7aec018e041b1e0b63a45962",
            hex::encode(hasher.finalize())
        );

        let mut public_key_bytes = Vec::<u8>::new();
        public_key
            .to_armored_writer(&mut public_key_bytes, None)
            .unwrap();

        let mut hasher = Sha256::new();
        hasher.update(&public_key_bytes);
        assert_eq!(
            "8074ddb524121edc31a1c6ce616ba37ac71412999802be804f252b33259fa0bc",
            hex::encode(hasher.finalize())
        );
    }
}
