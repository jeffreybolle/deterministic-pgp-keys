use crate::pgp::composed::{key::SecretKeyParamsBuilder, KeyType};
use crate::pgp::crypto::{hash::HashAlgorithm, sym::SymmetricKeyAlgorithm};
use crate::pgp::types::CompressionAlgorithm;
use crate::pgp::{SignedSecretKey, SubkeyParamsBuilder};
use bip39::Mnemonic;
use chrono::{DateTime, Utc};
use digest::{Digest};
use hkdf::Hkdf;
use rand::{CryptoRng, Rng, SeedableRng};
use sha3::Sha3_256;
use smallvec::*;

fn hash_email(email: &str) -> [u8; 32] {
    let mut hash = Sha3_256::new();
    hash.update(email.as_bytes());
    hash.finalize().try_into().unwrap()
}

fn derive_rng_seed(master_seed: &[u8; 64], salt: [u8; 32], index: u64) -> Result<[u8; 32], anyhow::Error> {
    let hkdf = Hkdf::<Sha3_256>::new(Some(salt.as_slice()), master_seed);
    let mut seed = [0u8; 32];
    hkdf.expand(format!("index_{}", index).as_bytes(), &mut seed)?;
    Ok(seed)
}

fn new_rng(seed: [u8; 32]) -> impl Rng + CryptoRng {
    rand_chacha::ChaCha20Rng::from_seed(seed.as_slice().try_into().unwrap())
}

pub fn generate_keys(
    mnemonic: Mnemonic,
    name: String,
    email_addresses: Vec<String>,
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

    assert!(
        !email_addresses.is_empty(),
        "email_addresses vector is empty"
    );
    let primary_user_id = format!("{} <{}>", name, email_addresses[0]);
    let salt = hash_email(&email_addresses[0]);

    let extra_user_ids: Vec<_> = email_addresses
        .iter()
        .skip(1)
        .map(|address| format!("{} <{}>", name, address))
        .collect();

    let mut key_material = Vec::new();

    for index in 1..=4 {
        let mut rng = new_rng(derive_rng_seed(&master_seed, salt, index)?);
        key_material.push(Some(
            KeyType::Rsa(4096).generate_with_rng(&mut rng, passphrase.clone())?,
        ));
    }

    let secret_key_params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Rsa(4096))
        .can_create_certificates(true)
        .can_sign(false)
        .can_encrypt(false)
        .primary_user_id(primary_user_id)
        .user_ids(extra_user_ids)
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

    let mut rng = new_rng(derive_rng_seed(&master_seed, salt, 5)?);
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
            vec!["jeffreybolle@gmail.com".to_string()],
            Utc.from_utc_datetime(
                &NaiveDate::from_ymd_opt(2022, 9, 21)
                    .unwrap()
                    .and_hms_opt(0, 0, 0)
                    .unwrap(),
            ),
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
            "37cf6cc556e27c35a1e9325587079d651e5ca5fd77851676b4929560460c6626",
            hex::encode(hasher.finalize())
        );

        let mut public_key_bytes = Vec::<u8>::new();
        public_key
            .to_armored_writer(&mut public_key_bytes, None)
            .unwrap();

        let mut hasher = Sha256::new();
        hasher.update(&public_key_bytes);
        assert_eq!(
            "074722130decd18b9a1eaf1219d5bb358745c517a8af9c3d6a81ead03e25ad50",
            hex::encode(hasher.finalize())
        );
    }
}
