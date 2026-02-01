use chrono::{DateTime, TimeZone, Utc};
use nom::{
    combinator::{map, map_opt, rest},
    number::complete::{be_u16, be_u32, be_u8},
    IResult, Parser,
};
use num_traits::FromPrimitive;

use crate::pgp::crypto::PublicKeyAlgorithm;
use crate::pgp::packet::public_key_parser::parse_pub_fields;
use crate::pgp::types::{KeyVersion, PublicParams, SecretParams};

// Parse the whole private key, both public and private fields.
fn parse_pub_priv_fields(
    typ: PublicKeyAlgorithm,
) -> impl Fn(&[u8]) -> IResult<&[u8], (PublicParams, SecretParams)> {
    move |input| {
        let (input, pub_params) = parse_pub_fields(typ)(input)?;
        let (input, remaining) = rest(input)?;
        let priv_params = SecretParams::from_slice(remaining, typ).map_err(|_| {
            nom::Err::Error(nom::error::Error::new(input, nom::error::ErrorKind::Fail))
        })?;
        Ok((input, (pub_params, priv_params)))
    }
}

fn new_private_key_parser(
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
        SecretParams,
    ),
> {
    move |input| {
        let (input, created_at) =
            map(be_u32, |v| Utc.timestamp_opt(i64::from(v), 0).unwrap()).parse(input)?;
        let (input, alg) = map_opt(be_u8, PublicKeyAlgorithm::from_u8).parse(input)?;
        let (input, params) = parse_pub_priv_fields(alg)(input)?;
        Ok((input, (key_ver, alg, created_at, None, params.0, params.1)))
    }
}

fn old_private_key_parser(
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
        SecretParams,
    ),
> {
    move |input| {
        let (input, created_at) =
            map(be_u32, |v| Utc.timestamp_opt(i64::from(v), 0).unwrap()).parse(input)?;
        let (input, exp) = be_u16(input)?;
        let (input, alg) = map_opt(be_u8, PublicKeyAlgorithm::from_u8).parse(input)?;
        let (input, params) = parse_pub_priv_fields(alg)(input)?;
        Ok((
            input,
            (key_ver, alg, created_at, Some(exp), params.0, params.1),
        ))
    }
}

// Parse a private key packet (Tag 5)
// Ref: https://tpools.ietf.org/html/rfc4880.html#section-5.5.1.3
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
        SecretParams,
    ),
> {
    let (input, key_ver) = map_opt(be_u8, KeyVersion::from_u8).parse(input)?;
    match key_ver {
        KeyVersion::V2 | KeyVersion::V3 => old_private_key_parser(key_ver)(input),
        KeyVersion::V4 => new_private_key_parser(key_ver)(input),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Switch,
        ))),
    }
}
