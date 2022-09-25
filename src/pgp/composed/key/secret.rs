use smallvec::SmallVec;

use crate::pgp::composed::{KeyDetails, PublicSubkey, SignedSecretKey, SignedSecretSubKey};
use crate::pgp::crypto::{HashAlgorithm, PublicKeyAlgorithm};
use crate::pgp::errors::Result;
use crate::pgp::packet::{self, KeyFlags, SignatureConfigBuilder, SignatureType, Subpacket};
use crate::pgp::types::{KeyId, KeyTrait, SecretKeyTrait};
use chrono::{DateTime, SubsecRound, Utc};

/// User facing interface to work with a secret key.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SecretKey {
    primary_key: packet::SecretKey,
    details: KeyDetails,
    public_subkeys: Vec<PublicSubkey>,
    secret_subkeys: Vec<SecretSubkey>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SecretSubkey {
    key: packet::SecretSubkey,
    keyflags: KeyFlags,
}

impl SecretKey {
    pub fn new(
        primary_key: packet::SecretKey,
        details: KeyDetails,
        public_subkeys: Vec<PublicSubkey>,
        secret_subkeys: Vec<SecretSubkey>,
    ) -> Self {
        SecretKey {
            primary_key,
            details,
            public_subkeys,
            secret_subkeys,
        }
    }

    pub fn sign<F>(self, key_pw: F, datetime: DateTime<Utc>) -> Result<SignedSecretKey>
    where
        F: (FnOnce() -> String) + Clone,
    {
        let primary_key = self.primary_key;
        let details = self.details.sign(&primary_key, key_pw.clone(), datetime)?;
        let public_subkeys = self
            .public_subkeys
            .into_iter()
            .map(|k| k.sign(&primary_key, key_pw.clone()))
            .collect::<Result<Vec<_>>>()?;
        let secret_subkeys = self
            .secret_subkeys
            .into_iter()
            .map(|k| k.sign(&primary_key, key_pw.clone(), datetime))
            .collect::<Result<Vec<_>>>()?;

        Ok(SignedSecretKey {
            primary_key,
            details,
            public_subkeys,
            secret_subkeys,
        })
    }
}

impl KeyTrait for SecretKey {
    fn fingerprint(&self) -> Vec<u8> {
        self.primary_key.fingerprint()
    }

    fn key_id(&self) -> KeyId {
        self.primary_key.key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.primary_key.algorithm()
    }
}

impl SecretSubkey {
    pub fn new(key: packet::SecretSubkey, keyflags: KeyFlags) -> Self {
        SecretSubkey { key, keyflags }
    }

    pub fn sign<F>(
        self,
        sec_key: &impl SecretKeyTrait,
        key_pw: F,
        datetime: DateTime<Utc>,
    ) -> Result<SignedSecretSubKey>
    where
        F: (FnOnce() -> String) + Clone,
    {
        let key = self.key;
        let hashed_subpackets = vec![
            Subpacket::SignatureCreationTime(datetime.trunc_subsecs(0)),
            Subpacket::KeyFlags(self.keyflags.into()),
            Subpacket::IssuerFingerprint(
                Default::default(),
                SmallVec::from_slice(&sec_key.fingerprint()),
            ),
        ];

        let mut unhashed_sub_packets = vec![];

        if self.keyflags.sign() {
            let config = SignatureConfigBuilder::default()
                .typ(SignatureType::KeyBinding)
                .pub_alg(sec_key.algorithm())
                .hash_alg(HashAlgorithm::SHA2_512) // TODO use preferred hashing algo
                .hashed_subpackets(vec![
                    Subpacket::IssuerFingerprint(
                        Default::default(),
                        SmallVec::from_slice(&key.fingerprint()),
                    ),
                    Subpacket::SignatureCreationTime(datetime.trunc_subsecs(0)),
                ])
                .unhashed_subpackets(vec![Subpacket::Issuer(key.key_id())])
                .build()?;
            let signature = config.sign_key_binding(&key, key_pw.clone(), &sec_key)?;
            unhashed_sub_packets.push(Subpacket::EmbeddedSignature(Box::new(signature)));
        }

        unhashed_sub_packets.push(Subpacket::Issuer(sec_key.key_id()));

        let config = SignatureConfigBuilder::default()
            .typ(SignatureType::SubkeyBinding)
            .pub_alg(sec_key.algorithm())
            .hash_alg(HashAlgorithm::SHA2_512) // TODO use preferred hashing algo
            .hashed_subpackets(hashed_subpackets)
            .unhashed_subpackets(unhashed_sub_packets)
            .build()?;
        let signatures = vec![config.sign_subkey_binding(sec_key, key_pw, &key)?];

        Ok(SignedSecretSubKey { key, signatures })
    }
}

impl KeyTrait for SecretSubkey {
    fn fingerprint(&self) -> Vec<u8> {
        self.key.fingerprint()
    }

    fn key_id(&self) -> KeyId {
        self.key.key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.key.algorithm()
    }
}
