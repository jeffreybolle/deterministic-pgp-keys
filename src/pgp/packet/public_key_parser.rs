use chrono::{DateTime, TimeZone, Utc};
use nom::{
    bytes::complete::{tag, take},
    combinator::{map, map_opt},
    number::complete::{be_u16, be_u32, be_u8},
    IResult, Parser,
};
use num_traits::FromPrimitive;

use crate::pgp::crypto::ecc_curve::ecc_curve_from_oid;
use crate::pgp::crypto::{HashAlgorithm, PublicKeyAlgorithm, SymmetricKeyAlgorithm};
use crate::pgp::types::{mpi, KeyVersion, Mpi, MpiRef, PublicParams};

#[inline]
fn to_owned(mref: MpiRef<'_>) -> Mpi {
    mref.to_owned()
}

// Ref: https://tools.ietf.org/html/rfc6637#section-9
fn ecdsa(input: &[u8]) -> IResult<&[u8], PublicParams> {
    // a one-octet size of the following field
    let (input, len) = be_u8(input)?;
    // octets representing a curve OID
    let (input, curve) = map_opt(take(len), ecc_curve_from_oid).parse(input)?;
    // MPI of an EC point representing a public key
    let (input, p) = mpi(input)?;
    Ok((
        input,
        PublicParams::ECDSA {
            curve,
            p: p.to_owned(),
        },
    ))
}

// https://tools.ietf.org/html/draft-koch-eddsa-for-openpgp-00#section-4
fn eddsa(input: &[u8]) -> IResult<&[u8], PublicParams> {
    // a one-octet size of the following field
    let (input, len) = be_u8(input)?;
    // octets representing a curve OID
    let (input, curve) = map_opt(take(len), ecc_curve_from_oid).parse(input)?;
    // MPI of an EC point representing a public key
    let (input, q) = mpi(input)?;
    Ok((
        input,
        PublicParams::EdDSA {
            curve,
            q: q.to_owned(),
        },
    ))
}

// Ref: https://tools.ietf.org/html/rfc6637#section-9
fn ecdh(input: &[u8]) -> IResult<&[u8], PublicParams> {
    // a one-octet size of the following field
    let (input, len) = be_u8(input)?;
    // octets representing a curve OID
    let (input, curve) = map_opt(take(len), ecc_curve_from_oid).parse(input)?;
    // MPI of an EC point representing a public key
    let (input, p) = mpi(input)?;
    // a one-octet size of the following fields
    let (input, _len2) = be_u8(input)?;
    // a one-octet value 01, reserved for future extensions
    let (input, _) = tag(&[1][..])(input)?;
    // a one-octet hash function ID used with a KDF
    let (input, hash) = map_opt(be_u8, HashAlgorithm::from_u8).parse(input)?;
    // a one-octet algorithm ID for the symmetric algorithm used to wrap
    // the symmetric key used for the message encryption
    let (input, alg_sym) = map_opt(be_u8, SymmetricKeyAlgorithm::from_u8).parse(input)?;
    Ok((
        input,
        PublicParams::ECDH {
            curve,
            p: p.to_owned(),
            hash,
            alg_sym,
        },
    ))
}

fn elgamal(input: &[u8]) -> IResult<&[u8], PublicParams> {
    // MPI of Elgamal prime p
    let (input, p) = map(mpi, to_owned).parse(input)?;
    // MPI of Elgamal group generator g
    let (input, g) = map(mpi, to_owned).parse(input)?;
    // MPI of Elgamal public key value y (= g**x mod p where x is secret)
    let (input, y) = map(mpi, to_owned).parse(input)?;
    Ok((input, PublicParams::Elgamal { p, g, y }))
}

fn dsa(input: &[u8]) -> IResult<&[u8], PublicParams> {
    let (input, p) = map(mpi, to_owned).parse(input)?;
    let (input, q) = map(mpi, to_owned).parse(input)?;
    let (input, g) = map(mpi, to_owned).parse(input)?;
    let (input, y) = map(mpi, to_owned).parse(input)?;
    Ok((input, PublicParams::DSA { p, q, g, y }))
}

fn rsa(input: &[u8]) -> IResult<&[u8], PublicParams> {
    let (input, n) = map(mpi, to_owned).parse(input)?;
    let (input, e) = map(mpi, to_owned).parse(input)?;
    Ok((input, PublicParams::RSA { n, e }))
}

// Parse the fields of a public key.
pub fn parse_pub_fields(typ: PublicKeyAlgorithm) -> impl Fn(&[u8]) -> IResult<&[u8], PublicParams> {
    move |input| match typ {
        PublicKeyAlgorithm::RSA
        | PublicKeyAlgorithm::RSAEncrypt
        | PublicKeyAlgorithm::RSASign => rsa(input),
        PublicKeyAlgorithm::DSA => dsa(input),
        PublicKeyAlgorithm::ECDSA => ecdsa(input),
        PublicKeyAlgorithm::ECDH => ecdh(input),
        PublicKeyAlgorithm::Elgamal | PublicKeyAlgorithm::ElgamalSign => elgamal(input),
        PublicKeyAlgorithm::EdDSA => eddsa(input),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Switch,
        ))),
    }
}

fn new_public_key_parser(
    key_ver: KeyVersion,
) -> impl Fn(
    &[u8],
) -> IResult<
    &[u8],
    (
        KeyVersion,
        PublicKeyAlgorithm,
        DateTime<Utc>,
        Option<u16>,
        PublicParams,
    ),
> {
    move |input| {
        let (input, created_at) =
            map(be_u32, |v| Utc.timestamp_opt(i64::from(v), 0).unwrap()).parse(input)?;
        let (input, alg) = map_opt(be_u8, PublicKeyAlgorithm::from_u8).parse(input)?;
        let (input, params) = parse_pub_fields(alg)(input)?;
        Ok((input, (key_ver, alg, created_at, None, params)))
    }
}

fn old_public_key_parser(
    key_ver: KeyVersion,
) -> impl Fn(
    &[u8],
) -> IResult<
    &[u8],
    (
        KeyVersion,
        PublicKeyAlgorithm,
        DateTime<Utc>,
        Option<u16>,
        PublicParams,
    ),
> {
    move |input| {
        let (input, created_at) =
            map(be_u32, |v| Utc.timestamp_opt(i64::from(v), 0).unwrap()).parse(input)?;
        let (input, exp) = be_u16(input)?;
        let (input, alg) = map_opt(be_u8, PublicKeyAlgorithm::from_u8).parse(input)?;
        let (input, params) = parse_pub_fields(alg)(input)?;
        Ok((input, (key_ver, alg, created_at, Some(exp), params)))
    }
}

// Parse a public key packet (Tag 6)
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.5.1.1
pub fn parse(
    input: &[u8],
) -> IResult<
    &[u8],
    (
        KeyVersion,
        PublicKeyAlgorithm,
        DateTime<Utc>,
        Option<u16>,
        PublicParams,
    ),
> {
    let (input, key_ver) = map_opt(be_u8, KeyVersion::from_u8).parse(input)?;
    match key_ver {
        KeyVersion::V2 | KeyVersion::V3 => old_public_key_parser(key_ver)(input),
        KeyVersion::V4 => new_public_key_parser(key_ver)(input),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Switch,
        ))),
    }
}
