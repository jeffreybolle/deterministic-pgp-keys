use std::io;

use nom::{
    bytes::complete::take,
    combinator::{cond, map_opt},
    number::complete::be_u8,
    IResult, Parser,
};
use num_traits::FromPrimitive;
use zeroize::Zeroize;

use crate::pgp::crypto::public_key::PublicKeyAlgorithm;
use crate::pgp::crypto::sym::SymmetricKeyAlgorithm;
use crate::pgp::errors::Result;
use crate::pgp::ser::Serialize;
use crate::pgp::types::*;

/// A list of params that are used to represent the values of possibly encrypted key,
/// from imports and exports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretParams {
    Plain(PlainSecretParams),
    Encrypted(EncryptedSecretParams),
}

impl Zeroize for SecretParams {
    fn zeroize(&mut self) {
        match self {
            SecretParams::Plain(p) => p.zeroize(),
            SecretParams::Encrypted(_) => { /* encrypted params do not need zeroing */ }
        }
    }
}

impl SecretParams {
    pub fn is_encrypted(&self) -> bool {
        match self {
            SecretParams::Plain(_) => false,
            SecretParams::Encrypted(_) => true,
        }
    }

    pub fn from_slice(data: &[u8], alg: PublicKeyAlgorithm) -> Result<Self> {
        let (_, (params, cs)) = parse_secret_fields(data, alg)?;

        params.compare_checksum(cs)?;

        Ok(params)
    }

    pub fn string_to_key_id(&self) -> u8 {
        match self {
            SecretParams::Plain(k) => k.string_to_key_id(),
            SecretParams::Encrypted(k) => k.string_to_key_id(),
        }
    }

    pub fn compare_checksum(&self, other: Option<&[u8]>) -> Result<()> {
        match self {
            SecretParams::Plain(k) => k.as_ref().compare_checksum_simple(other),
            SecretParams::Encrypted(k) => k.compare_checksum(other),
        }
    }

    pub fn checksum(&self) -> Option<Vec<u8>> {
        match self {
            SecretParams::Plain(k) => Some(k.checksum_simple()),
            SecretParams::Encrypted(k) => k.checksum(),
        }
    }
}

impl Serialize for SecretParams {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            SecretParams::Plain(k) => k.to_writer(writer),
            SecretParams::Encrypted(k) => k.to_writer(writer),
        }
    }
}

// Parse possibly encrypted private fields of a key.
fn parse_secret_fields(
    input: &[u8],
    alg: PublicKeyAlgorithm,
) -> IResult<&[u8], (SecretParams, Option<&[u8]>)> {
    let (input, s2k_typ) = be_u8(input)?;

    // Parse encryption parameters based on s2k_typ
    let (input, enc_params): (
        &[u8],
        (
            Option<SymmetricKeyAlgorithm>,
            Option<&[u8]>,
            Option<StringToKey>,
        ),
    ) = match s2k_typ {
        // 0 is no encryption
        0 => (input, (None, None, None)),
        // symmetric key algorithm
        1..=253 => {
            let sym_alg =
                SymmetricKeyAlgorithm::from_u8(s2k_typ).ok_or_else(|| {
                    nom::Err::Error(nom::error::Error::new(
                        input,
                        nom::error::ErrorKind::MapOpt,
                    ))
                })?;
            let (input, iv) = take(sym_alg.block_size())(input)?;
            (input, (Some(sym_alg), Some(iv), None))
        }
        // symmetric key + string-to-key
        254..=255 => {
            let (input, sym_alg) = map_opt(be_u8, SymmetricKeyAlgorithm::from_u8).parse(input)?;
            let (input, s2k) = s2k_parser(input)?;
            let (input, iv) = take(sym_alg.block_size())(input)?;
            (input, (Some(sym_alg), Some(iv), Some(s2k)))
        }
    };

    // Determine checksum length
    let checksum_len: usize = match s2k_typ {
        // 20 octet hash at the end, but part of the encrypted part
        254 => 0,
        // 2 octet checksum at the end
        _ => 2,
    };

    // Calculate data length (remaining input minus checksum)
    let data_len = input.len() - checksum_len;

    let (input, data) = take(data_len)(input)?;
    let (input, checksum) = cond(checksum_len > 0, take(checksum_len)).parse(input)?;

    let encryption_algorithm = enc_params.0;
    let iv = enc_params.1.map(|iv| iv.to_vec());
    let string_to_key = enc_params.2;

    let res = match s2k_typ {
        0 => {
            let repr = PlainSecretParams::from_slice(data, alg).map_err(|_| {
                nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Fail))
            })?;
            SecretParams::Plain(repr)
        }
        _ => SecretParams::Encrypted(EncryptedSecretParams::new(
            data.to_vec(),
            iv.expect("encrypted"),
            encryption_algorithm.expect("encrypted"),
            string_to_key.expect("encrypted"),
            s2k_typ,
        )),
    };
    Ok((input, (res, checksum)))
}
