#[macro_export]
macro_rules! impl_public_key {
    ($name:ident, $tag:expr) => {
        #[derive(Debug, PartialEq, Eq, Clone)]
        pub struct $name {
            pub(crate) packet_version: $crate::pgp::types::Version,
            pub(crate) version: $crate::pgp::types::KeyVersion,
            pub(crate) algorithm: $crate::pgp::crypto::public_key::PublicKeyAlgorithm,
            pub(crate) created_at: chrono::DateTime<chrono::Utc>,
            pub(crate) expiration: Option<u16>,
            pub(crate) public_params: $crate::pgp::types::PublicParams,
        }

        impl $name {
            /// Create a new `PublicKeyKey` packet from underlying parameters.
            pub fn new(
                packet_version: $crate::pgp::types::Version,
                version: $crate::pgp::types::KeyVersion,
                algorithm: $crate::pgp::crypto::public_key::PublicKeyAlgorithm,
                created_at: chrono::DateTime<chrono::Utc>,
                expiration: Option<u16>,
                public_params: $crate::pgp::types::PublicParams,
            ) -> $crate::pgp::errors::Result<Self> {
                use $crate::pgp::crypto::PublicKeyAlgorithm;
                use $crate::pgp::types::KeyVersion;

                if version == KeyVersion::V2 || version == KeyVersion::V3 {
                    ensure!(
                        algorithm == PublicKeyAlgorithm::RSA
                            || algorithm == PublicKeyAlgorithm::RSAEncrypt
                            || algorithm == PublicKeyAlgorithm::RSASign,
                        "Invalid algorithm {:?} for key version: {:?}",
                        algorithm,
                        version,
                    );
                }

                Ok($name {
                    packet_version,
                    version,
                    algorithm,
                    created_at,
                    expiration,
                    public_params,
                })
            }

            /// Parses a `PublicKeyKey` packet from the given slice.
            pub fn from_slice(
                packet_version: $crate::pgp::types::Version,
                input: &[u8],
            ) -> $crate::pgp::errors::Result<Self> {
                let (_, details) = $crate::pgp::packet::public_key_parser::parse(input)?;
                let (version, algorithm, created_at, expiration, public_params) = details;

                $name::new(
                    packet_version,
                    version,
                    algorithm,
                    created_at,
                    expiration,
                    public_params,
                )
            }

            pub fn version(&self) -> $crate::pgp::types::KeyVersion {
                self.version
            }

            pub fn created_at(&self) -> &chrono::DateTime<chrono::Utc> {
                &self.created_at
            }

            pub fn expiration(&self) -> Option<u16> {
                self.expiration
            }

            pub fn public_params(&self) -> &$crate::pgp::types::PublicParams {
                &self.public_params
            }

            pub fn verify(&self) -> $crate::pgp::errors::Result<()> {
                unimplemented!("verify");
            }

            fn to_writer_old<W: std::io::Write>(
                &self,
                writer: &mut W,
            ) -> $crate::pgp::errors::Result<()> {
                use byteorder::{BigEndian, WriteBytesExt};
                use $crate::pgp::ser::Serialize;

                writer.write_u32::<BigEndian>(self.created_at.timestamp() as u32)?;
                writer.write_u16::<BigEndian>(
                    self.expiration
                        .expect("old key versions have an expiration"),
                )?;
                writer.write_all(&[self.algorithm as u8])?;
                self.public_params.to_writer(writer)?;

                Ok(())
            }

            fn to_writer_new<W: std::io::Write>(
                &self,
                writer: &mut W,
            ) -> $crate::pgp::errors::Result<()> {
                use byteorder::{BigEndian, WriteBytesExt};
                use $crate::pgp::ser::Serialize;

                writer.write_u32::<BigEndian>(self.created_at.timestamp() as u32)?;
                writer.write_all(&[self.algorithm as u8])?;
                self.public_params.to_writer(writer)?;

                Ok(())
            }

            pub fn sign<F>(
                &self,
                key: &impl $crate::pgp::types::SecretKeyTrait,
                key_pw: F,
            ) -> $crate::pgp::errors::Result<$crate::pgp::packet::Signature>
            where
                F: FnOnce() -> String,
            {
                use chrono::SubsecRound;

                let mut config = $crate::pgp::packet::SignatureConfigBuilder::default();
                match $tag {
                    $crate::pgp::types::Tag::PublicKey => {
                        config.typ($crate::pgp::packet::SignatureType::KeyBinding);
                    }
                    $crate::pgp::types::Tag::PublicSubkey => {
                        config.typ($crate::pgp::packet::SignatureType::SubkeyBinding);
                    }
                    _ => panic!("invalid tag"),
                };

                config
                    .pub_alg(key.algorithm())
                    .hash_alg($crate::pgp::crypto::hash::HashAlgorithm::SHA2_512) // TODO use preferred hashing algo
                    .hashed_subpackets(vec![$crate::pgp::packet::Subpacket::SignatureCreationTime(
                        chrono::Utc::now().trunc_subsecs(0),
                    )])
                    .unhashed_subpackets(vec![$crate::pgp::packet::Subpacket::Issuer(key.key_id())])
                    .build()?
                    .sign_key(key, key_pw, &self)
            }
        }

        impl $crate::pgp::ser::Serialize for $name {
            fn to_writer<W: std::io::Write>(
                &self,
                writer: &mut W,
            ) -> $crate::pgp::errors::Result<()> {
                writer.write_all(&[self.version as u8])?;

                match self.version {
                    $crate::pgp::types::KeyVersion::V2 | $crate::pgp::types::KeyVersion::V3 => {
                        self.to_writer_old(writer)
                    }
                    $crate::pgp::types::KeyVersion::V4 => self.to_writer_new(writer),
                    $crate::pgp::types::KeyVersion::V5 => unimplemented_err!("V5 keys"),
                }
            }
        }

        impl $crate::pgp::packet::PacketTrait for $name {
            fn packet_version(&self) -> $crate::pgp::types::Version {
                self.packet_version
            }

            fn tag(&self) -> $crate::pgp::types::Tag {
                $tag
            }
        }

        impl $crate::pgp::types::KeyTrait for $name {
            /// Returns the fingerprint of this key.
            fn fingerprint(&self) -> Vec<u8> {
                use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
                use md5::Md5;
                use sha1::{Digest, Sha1};

                use $crate::pgp::ser::Serialize;
                use $crate::pgp::types::KeyVersion;

                match self.version() {
                    KeyVersion::V5 => unimplemented!("V5 keys"),
                    KeyVersion::V4 => {
                        // A one-octet version number (4).
                        let mut packet = vec![4, 0, 0, 0, 0];

                        // A four-octet number denoting the time that the key was created.
                        BigEndian::write_u32(
                            &mut packet[1..5],
                            self.created_at().timestamp() as u32,
                        );

                        // A one-octet number denoting the public-key algorithm of this key.
                        packet.push(self.algorithm() as u8);
                        self.public_params
                            .to_writer(&mut packet)
                            .expect("write to vec");

                        let mut h = Sha1::new();
                        h.update(&[0x99]);
                        h.write_u16::<BigEndian>(packet.len() as u16)
                            .expect("write to hasher");
                        h.update(&packet);

                        h.finalize().to_vec()
                    }
                    KeyVersion::V2 | KeyVersion::V3 => {
                        let mut h = Md5::new();
                        self.public_params
                            .to_writer(&mut h)
                            .expect("write to hasher");
                        h.finalize().to_vec()
                    }
                }
            }

            fn key_id(&self) -> $crate::pgp::types::KeyId {
                use $crate::pgp::types::{KeyId, KeyVersion, PublicParams};

                match self.version() {
                    KeyVersion::V5 => unimplemented!("V5 keys"),
                    KeyVersion::V4 => {
                        // Lower 64 bits
                        let f = self.fingerprint();
                        let offset = f.len() - 8;

                        KeyId::from_slice(&f[offset..]).expect("fixed size slice")
                    }
                    KeyVersion::V2 | KeyVersion::V3 => match &self.public_params {
                        PublicParams::RSA { n, .. } => {
                            let offset = n.len() - 8;

                            KeyId::from_slice(&n.as_bytes()[offset..]).expect("fixed size slice")
                        }
                        _ => panic!("invalid key constructed: {:?}", &self.public_params),
                    },
                }
            }

            fn algorithm(&self) -> $crate::pgp::crypto::public_key::PublicKeyAlgorithm {
                self.algorithm
            }
        }

        impl $crate::pgp::types::PublicKeyTrait for $name {
            fn verify_signature(
                &self,
                hash: $crate::pgp::crypto::hash::HashAlgorithm,
                hashed: &[u8],
                sig: &[$crate::pgp::types::Mpi],
            ) -> $crate::pgp::errors::Result<()> {
                use $crate::pgp::types::PublicParams;

                match self.public_params {
                    PublicParams::RSA { ref n, ref e } => {
                        ensure_eq!(sig.len(), 1, "invalid signature");
                        $crate::pgp::crypto::rsa::verify(
                            n.as_bytes(),
                            e.as_bytes(),
                            hash,
                            hashed,
                            sig[0].as_bytes(),
                        )
                    }
                    PublicParams::EdDSA { ref curve, ref q } => {
                        $crate::pgp::crypto::eddsa::verify(curve, q.as_bytes(), hash, hashed, sig)
                    }
                    PublicParams::ECDSA { ref curve, .. } => {
                        unimplemented_err!("verify ECDSA: {:?}", curve);
                    }
                    PublicParams::ECDH {
                        ref curve,
                        ref hash,
                        ref alg_sym,
                        ..
                    } => {
                        unimplemented_err!("verify ECDH: {:?} {:?} {:?}", curve, hash, alg_sym);
                    }
                    PublicParams::Elgamal { .. } => {
                        unimplemented_err!("verify Elgamal");
                    }
                    PublicParams::DSA { .. } => {
                        unimplemented_err!("verify DSA");
                    }
                }
            }

            fn encrypt<R: rand::CryptoRng + rand::Rng>(
                &self,
                rng: &mut R,
                plain: &[u8],
            ) -> $crate::pgp::errors::Result<Vec<$crate::pgp::types::Mpi>> {
                use $crate::pgp::types::{KeyTrait, PublicParams};

                let res = match self.public_params {
                    PublicParams::RSA { ref n, ref e } => {
                        $crate::pgp::crypto::rsa::encrypt(rng, n.as_bytes(), e.as_bytes(), plain)
                    }
                    PublicParams::EdDSA { .. } => bail!("EdDSA is only used for signing"),
                    PublicParams::ECDSA { .. } => bail!("ECDSA is only used for signing"),
                    PublicParams::ECDH {
                        ref curve,
                        hash,
                        alg_sym,
                        ref p,
                    } => $crate::pgp::crypto::ecdh::encrypt(
                        rng,
                        curve,
                        alg_sym,
                        hash,
                        &self.fingerprint(),
                        p.as_bytes(),
                        plain,
                    ),
                    PublicParams::Elgamal { .. } => unimplemented_err!("encryption with Elgamal"),
                    PublicParams::DSA { .. } => bail!("DSA is only used for signing"),
                }?;

                Ok(res
                    .iter()
                    .map(|v| $crate::pgp::types::Mpi::from_raw_slice(&v[..]))
                    .collect::<Vec<_>>())
            }

            fn to_writer_old(
                &self,
                writer: &mut impl std::io::Write,
            ) -> $crate::pgp::errors::Result<()> {
                use $crate::pgp::ser::Serialize;

                let mut key_buf = Vec::new();
                self.to_writer(&mut key_buf)?;

                // old style packet header for the key
                writer.write_all(&[0x99, (key_buf.len() >> 8) as u8, key_buf.len() as u8])?;
                writer.write_all(&key_buf)?;

                Ok(())
            }
        }
    };
}
