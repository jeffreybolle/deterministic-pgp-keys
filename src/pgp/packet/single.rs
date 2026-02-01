use nom::{
    bits::complete::{tag as tag_bits, take as take_bits},
    branch::alt,
    bytes::complete::take,
    combinator::{map, map_opt},
    number::complete::{be_u32, be_u8},
    Err, IResult, Parser,
};
use num_traits::FromPrimitive;

use crate::pgp::de::Deserialize;
use crate::pgp::errors::{Error, Result};
use crate::pgp::packet::packet_sum::Packet;
use crate::pgp::packet::{
    CompressedData, LiteralData, Marker, ModDetectionCode, OnePassSignature, PublicKey,
    PublicKeyEncryptedSessionKey, PublicSubkey, SecretKey, SecretSubkey, Signature,
    SymEncryptedData, SymEncryptedProtectedData, SymKeyEncryptedSessionKey, Trust, UserAttribute,
    UserId,
};
use crate::pgp::types::{PacketLength, Tag, Version};
use crate::pgp::util::{u16_as_usize, u32_as_usize, u8_as_usize};

type BitInput<'a> = (&'a [u8], usize);

// Parses an old format packet header
// Ref: https://tools.ietf.org/html/rfc4880.html#section-4.2.1
fn old_packet_header_bits(input: BitInput<'_>) -> IResult<BitInput<'_>, (Version, Tag, PacketLength)> {
    // First bit is always 1
    let (input, _): (_, u8) = tag_bits(1u8, 1usize).parse(input)?;
    // Version: 0
    let (input, ver) = map_opt(|i| tag_bits(0u8, 1usize).parse(i), |v: u8| Version::from_u8(v)).parse(input)?;
    // Packet Tag
    let (input, tag) = map_opt(take_bits(4usize), Tag::from_u8).parse(input)?;
    // Packet Length Type
    let (input, len_type): (_, u8) = take_bits(2usize).parse(input)?;
    let (input, len) = match len_type {
        // One-Octet Lengths
        0 => {
            let (i, val): (_, u8) = take_bits(8usize).parse(input)?;
            (i, u8_as_usize(val).into())
        }
        // Two-Octet Lengths
        1 => {
            let (i, val): (_, u16) = take_bits(16usize).parse(input)?;
            (i, u16_as_usize(val).into())
        }
        // Four-Octet Lengths
        2 => {
            let (i, val): (_, u32) = take_bits(32usize).parse(input)?;
            (i, u32_as_usize(val).into())
        }
        3 => (input, PacketLength::Indeterminated),
        _ => unreachable!(),
    };
    Ok((input, (ver, tag, len)))
}

fn old_packet_header(input: &[u8]) -> IResult<&[u8], (Version, Tag, PacketLength)> {
    nom::bits::bits(old_packet_header_bits)(input)
}

fn read_packet_len(input: &[u8]) -> IResult<&[u8], PacketLength> {
    let (input, olen) = be_u8(input)?;
    match olen {
        // One-Octet Lengths
        0..=191 => Ok((input, (olen as usize).into())),
        // Two-Octet Lengths
        192..=223 => {
            let (input, a) = be_u8(input)?;
            Ok((input, (((olen as usize - 192) << 8) + 192 + a as usize).into()))
        }
        // Partial Body Lengths
        224..=254 => Ok((input, PacketLength::Partial(1 << (olen as usize & 0x1F)))),
        // Five-Octet Lengths
        255 => map(be_u32, |v| u32_as_usize(v).into()).parse(input),
    }
}

fn read_partial_bodies(input: &[u8], len: usize) -> IResult<&[u8], ParseResult<'_>> {
    if input.len() < len {
        return Err(Err::Incomplete(nom::Needed::new(len - input.len())));
    }

    let mut out = vec![&input[0..len]];

    let mut rest = &input[len..];

    loop {
        let res = read_packet_len(rest)?;
        match res.1 {
            PacketLength::Partial(len) => {
                if res.0.len() < len {
                    return Err(Err::Incomplete(nom::Needed::new(len - res.0.len())));
                }
                out.push(&res.0[0..len]);
                rest = &res.0[len..];
            }
            PacketLength::Fixed(len) => {
                if res.0.len() < len {
                    return Err(Err::Incomplete(nom::Needed::new(len - res.0.len())));
                }

                out.push(&res.0[0..len]);
                rest = &res.0[len..];
                // this is the last one
                break;
            }
            PacketLength::Indeterminated => {
                // this should not happen, as this is a new style
                // packet, but lets handle it anyway
                out.push(res.0);
                rest = &[];

                // we read everything
                break;
            }
        }
    }

    Ok((rest, ParseResult::Partial(out)))
}

// Parses a new format packet header
// Ref: https://tools.ietf.org/html/rfc4880.html#section-4.2.2
fn new_packet_header_bits(input: BitInput<'_>) -> IResult<BitInput<'_>, (Version, Tag, Option<PacketLength>)> {
    // First bit is always 1
    let (input, _): (_, u8) = tag_bits(1u8, 1usize).parse(input)?;
    // Version: 1
    let (input, ver) = map_opt(|i| tag_bits(1u8, 1usize).parse(i), |v: u8| Version::from_u8(v)).parse(input)?;
    // Packet Tag
    let (input, tag) = map_opt(take_bits(6usize), Tag::from_u8).parse(input)?;
    // Return None for len - we'll parse it after converting back to bytes
    Ok((input, (ver, tag, None)))
}

fn new_packet_header(input: &[u8]) -> IResult<&[u8], (Version, Tag, PacketLength)> {
    // First parse the bits part (first byte)
    let (input, (ver, tag, _)) = nom::bits::bits(new_packet_header_bits)(input)?;
    // Then parse the length as bytes
    let (input, len) = read_packet_len(input)?;
    Ok((input, (ver, tag, len)))
}

#[derive(Debug)]
pub enum ParseResult<'a> {
    Fixed(&'a [u8]),
    Indeterminated,
    Partial(Vec<&'a [u8]>),
}

// Parse a single Packet
// https://tools.ietf.org/html/rfc4880.html#section-4.2
pub fn parser(input: &[u8]) -> IResult<&[u8], (Version, Tag, PacketLength, ParseResult<'_>)> {
    let (input, head) = alt((new_packet_header, old_packet_header)).parse(input)?;
    let (input, body) = match &head.2 {
        PacketLength::Fixed(length) => {
            let (input, data) = take(*length)(input)?;
            (input, ParseResult::Fixed(data))
        }
        PacketLength::Indeterminated => (input, ParseResult::Indeterminated),
        PacketLength::Partial(length) => read_partial_bodies(input, *length)?,
    };
    Ok((input, (head.0, head.1, head.2, body)))
}

pub fn body_parser(ver: Version, tag: Tag, body: &[u8]) -> Result<Packet> {
    let res: Result<Packet> = match tag {
        Tag::PublicKeyEncryptedSessionKey => {
            PublicKeyEncryptedSessionKey::from_slice(ver, body).map(Into::into)
        }
        Tag::Signature => Signature::from_slice(ver, body).map(Into::into),
        Tag::SymKeyEncryptedSessionKey => {
            SymKeyEncryptedSessionKey::from_slice(ver, body).map(Into::into)
        }
        Tag::OnePassSignature => OnePassSignature::from_slice(ver, body).map(Into::into),
        Tag::SecretKey => SecretKey::from_slice(ver, body).map(Into::into),
        Tag::PublicKey => PublicKey::from_slice(ver, body).map(Into::into),
        Tag::SecretSubkey => SecretSubkey::from_slice(ver, body).map(Into::into),
        Tag::CompressedData => CompressedData::from_slice(ver, body).map(Into::into),
        Tag::SymEncryptedData => SymEncryptedData::from_slice(ver, body).map(Into::into),
        Tag::Marker => Marker::from_slice(ver, body).map(Into::into),
        Tag::LiteralData => LiteralData::from_slice(ver, body).map(Into::into),
        Tag::Trust => Trust::from_slice(ver, body).map(Into::into),
        Tag::UserId => UserId::from_slice(ver, body).map(Into::into),
        Tag::PublicSubkey => PublicSubkey::from_slice(ver, body).map(Into::into),
        Tag::UserAttribute => UserAttribute::from_slice(ver, body).map(Into::into),
        Tag::SymEncryptedProtectedData => {
            SymEncryptedProtectedData::from_slice(ver, body).map(Into::into)
        }
        Tag::ModDetectionCode => ModDetectionCode::from_slice(ver, body).map(Into::into),
    };

    match res {
        Ok(res) => Ok(res),
        Err(Error::Incomplete(n)) => Err(Error::Incomplete(n)),
        Err(err) => {
            warn!("invalid packet: {:?} {:?}\n{}", err, tag, hex::encode(body));
            Err(Error::InvalidPacketContent(Box::new(err)))
        }
    }
}
