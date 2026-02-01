use std::io;

use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use nom::{
    bytes::complete::take,
    combinator::{map, map_opt, map_res, success},
    number::complete::be_u8,
    IResult, Parser,
};
use num_traits::FromPrimitive;
use rand::{CryptoRng, Rng};

use crate::pgp::crypto::{checksum, PublicKeyAlgorithm, SymmetricKeyAlgorithm};
use crate::pgp::errors::Result;
use crate::pgp::packet::PacketTrait;
use crate::pgp::ser::Serialize;
use crate::pgp::types::{mpi, KeyId, Mpi, PublicKeyTrait, Tag, Version};

/// Public Key Encrypted Session Key Packet
/// https://tools.ietf.org/html/rfc4880.html#section-5.1
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyEncryptedSessionKey {
    packet_version: Version,
    version: u8,
    id: KeyId,
    algorithm: PublicKeyAlgorithm,
    mpis: Vec<Mpi>,
}

impl PublicKeyEncryptedSessionKey {
    /// Parses a `PublicKeyEncryptedSessionKey` packet from the given slice.
    pub fn from_slice(version: Version, input: &[u8]) -> Result<Self> {
        let (_, pk) = parse(version)(input)?;

        ensure_eq!(pk.version, 3, "invalid version");

        Ok(pk)
    }

    /// Encrypts the given session key to the passed in public key.
    pub fn from_session_key<R: CryptoRng + Rng>(
        rng: &mut R,
        session_key: &[u8],
        alg: SymmetricKeyAlgorithm,
        pkey: &impl PublicKeyTrait,
    ) -> Result<Self> {
        // the session key is prefixed with symmetric key algorithm
        let len = session_key.len();
        let mut data = vec![0u8; len + 3];
        data[0] = alg as u8;
        data[1..=len].copy_from_slice(session_key);

        // and appended a checksum
        BigEndian::write_u16(
            &mut data[len + 1..],
            checksum::calculate_simple(session_key),
        );

        let mpis = pkey.encrypt(rng, &data)?;

        Ok(PublicKeyEncryptedSessionKey {
            packet_version: Default::default(),
            version: 3,
            id: pkey.key_id(),
            algorithm: pkey.algorithm(),
            mpis,
        })
    }

    pub fn id(&self) -> &KeyId {
        &self.id
    }

    pub fn mpis(&self) -> &[Mpi] {
        &self.mpis
    }

    pub fn packet_version(&self) -> Version {
        self.packet_version
    }
}

fn parse_mpis(alg: PublicKeyAlgorithm) -> impl Fn(&[u8]) -> IResult<&[u8], Vec<Mpi>> {
    move |input| match alg {
        PublicKeyAlgorithm::RSA
        | PublicKeyAlgorithm::RSASign
        | PublicKeyAlgorithm::RSAEncrypt => map(mpi, |v| vec![v.to_owned()]).parse(input),
        PublicKeyAlgorithm::Elgamal | PublicKeyAlgorithm::ElgamalSign => {
            let (input, first) = mpi(input)?;
            let (input, second) = mpi(input)?;
            Ok((input, vec![first.to_owned(), second.to_owned()]))
        }
        PublicKeyAlgorithm::ECDSA | PublicKeyAlgorithm::DSA | PublicKeyAlgorithm::DiffieHellman => {
            success(Vec::new()).parse(input)
        }
        PublicKeyAlgorithm::ECDH => {
            let (input, a) = mpi(input)?;
            let (input, blen) = be_u8(input)?;
            let (input, b) = take(blen)(input)?;
            let v: [u8; 1] = [blen];
            Ok((input, vec![a.to_owned(), (&v[..]).into(), b.into()]))
        }
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Switch,
        ))),
    }
}

// Parses a Public-Key Encrypted Session Key Packets
fn parse(packet_version: Version) -> impl Fn(&[u8]) -> IResult<&[u8], PublicKeyEncryptedSessionKey> {
    move |input| {
        // version, only 3 is allowed
        let (input, version) = be_u8(input)?;
        // the key id this maps to
        let (input, id) = map_res(take(8usize), KeyId::from_slice).parse(input)?;
        // the symmetric key algorithm
        let (input, alg) = map_opt(be_u8, PublicKeyAlgorithm::from_u8).parse(input)?;
        // key algorithm specific data
        let (input, mpis) = parse_mpis(alg)(input)?;
        Ok((
            input,
            PublicKeyEncryptedSessionKey {
                packet_version,
                version,
                id,
                algorithm: alg,
                mpis,
            },
        ))
    }
}

impl Serialize for PublicKeyEncryptedSessionKey {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&[self.version])?;
        writer.write_all(self.id.as_ref())?;
        writer.write_all(&[self.algorithm as u8])?;

        match self.algorithm {
            PublicKeyAlgorithm::RSA
            | PublicKeyAlgorithm::RSASign
            | PublicKeyAlgorithm::RSAEncrypt
            | PublicKeyAlgorithm::Elgamal
            | PublicKeyAlgorithm::ElgamalSign => {
                for mpi in &self.mpis {
                    mpi.to_writer(writer)?;
                }
            }
            PublicKeyAlgorithm::ECDH => {
                self.mpis[0].to_writer(writer)?;
                // The second value is not encoded as an actual MPI, but rather as a length prefixed
                // number.
                let blen: usize = match self.mpis[1].first() {
                    Some(l) => *l as usize,
                    None => 0,
                };
                writer.write_all(&[blen as u8])?;
                let padding_len = blen - self.mpis[2].as_bytes().len();
                for _ in 0..padding_len {
                    writer.write_u8(0)?;
                }
                writer.write_all(self.mpis[2].as_bytes())?;
            }
            _ => {
                unimplemented_err!("writing {:?}", self.algorithm);
            }
        }

        Ok(())
    }
}

impl PacketTrait for PublicKeyEncryptedSessionKey {
    fn packet_version(&self) -> Version {
        self.packet_version
    }

    fn tag(&self) -> Tag {
        Tag::PublicKeyEncryptedSessionKey
    }
}
