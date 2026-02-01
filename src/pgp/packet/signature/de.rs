use std::boxed::Box;
use std::str;

use chrono::{DateTime, NaiveDateTime, TimeZone, Utc};
use nom::{
    bytes::complete::{tag, take},
    combinator::{complete, map, map_opt, map_res, rest},
    multi::{fold_many_m_n, many0},
    number::complete::{be_u16, be_u32, be_u8},
    IResult, Parser,
};
use num_traits::FromPrimitive;
use smallvec::SmallVec;

use crate::pgp::crypto::aead::AeadAlgorithm;
use crate::pgp::crypto::hash::HashAlgorithm;
use crate::pgp::crypto::public_key::PublicKeyAlgorithm;
use crate::pgp::crypto::sym::SymmetricKeyAlgorithm;
use crate::pgp::de::Deserialize;
use crate::pgp::errors::Result;
use crate::pgp::packet::signature::types::*;
use crate::pgp::types::{
    mpi, CompressionAlgorithm, KeyId, KeyVersion, Mpi, MpiRef, RevocationKey, RevocationKeyClass,
    Version,
};
use crate::pgp::util::{clone_into_array, packet_length, read_string};

impl Deserialize for Signature {
    /// Parses a `Signature` packet from the given slice.
    fn from_slice(packet_version: Version, input: &[u8]) -> Result<Self> {
        let (_, pk) = parse(packet_version)(input)?;

        Ok(pk)
    }
}

/// Convert an epoch timestamp to a `DateTime`
fn dt_from_timestamp(ts: u32) -> DateTime<Utc> {
    DateTime::<Utc>::from_utc(
        NaiveDateTime::from_timestamp_opt(i64::from(ts), 0).expect("valid timestamp"),
        Utc,
    )
}

// Parse a signature creation time subpacket
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.4
fn signature_creation_time(input: &[u8]) -> IResult<&[u8], Subpacket> {
    map(be_u32, |date| {
        Subpacket::SignatureCreationTime(dt_from_timestamp(date))
    }).parse(input)
}

// Parse an issuer subpacket
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.5
fn issuer(input: &[u8]) -> IResult<&[u8], Subpacket> {
    map(map_res(complete(take(8usize)), KeyId::from_slice), Subpacket::Issuer).parse(input)
}

// Parse a key expiration time subpacket
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.6
fn key_expiration(input: &[u8]) -> IResult<&[u8], Subpacket> {
    map(be_u32, |date| {
        Subpacket::KeyExpirationTime(dt_from_timestamp(date))
    }).parse(input)
}

/// Parse a preferred symmetric algorithms subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.7
fn pref_sym_alg(body: &[u8]) -> IResult<&[u8], Subpacket> {
    let list: SmallVec<[SymmetricKeyAlgorithm; 8]> = body
        .iter()
        .map(|v| {
            SymmetricKeyAlgorithm::from_u8(*v)
                .ok_or_else(|| format_err!("Invalid SymmetricKeyAlgorithm"))
        })
        .collect::<Result<_>>()?;

    Ok((&b""[..], Subpacket::PreferredSymmetricAlgorithms(list)))
}

/// Parse a preferred hash algorithms subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.8
fn pref_hash_alg(body: &[u8]) -> IResult<&[u8], Subpacket> {
    let list: SmallVec<[HashAlgorithm; 8]> = body
        .iter()
        .map(|v| HashAlgorithm::from_u8(*v).ok_or_else(|| format_err!("Invalid HashAlgorithm")))
        .collect::<Result<_>>()?;

    Ok((&b""[..], Subpacket::PreferredHashAlgorithms(list)))
}

/// Parse a preferred compression algorithms subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.9
fn pref_com_alg(body: &[u8]) -> IResult<&[u8], Subpacket> {
    let list: SmallVec<[CompressionAlgorithm; 8]> = body
        .iter()
        .map(|v| {
            CompressionAlgorithm::from_u8(*v)
                .ok_or_else(|| format_err!("Invalid CompressionAlgorithm"))
        })
        .collect::<Result<_>>()?;

    Ok((&b""[..], Subpacket::PreferredCompressionAlgorithms(list)))
}

// Parse a signature expiration time subpacket
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.10
fn signature_expiration_time(input: &[u8]) -> IResult<&[u8], Subpacket> {
    map(be_u32, |date| {
        Subpacket::SignatureExpirationTime(dt_from_timestamp(date))
    }).parse(input)
}

// Parse a exportable certification subpacket.
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.11
fn exportable_certification(input: &[u8]) -> IResult<&[u8], Subpacket> {
    map(complete(be_u8), |v| {
        Subpacket::ExportableCertification(v == 1)
    }).parse(input)
}

// Parse a revocable subpacket
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.12
fn revocable(input: &[u8]) -> IResult<&[u8], Subpacket> {
    map(complete(be_u8), |v| Subpacket::Revocable(v == 1)).parse(input)
}

// Parse a trust signature subpacket.
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.13
fn trust_signature(input: &[u8]) -> IResult<&[u8], Subpacket> {
    let (input, depth) = be_u8(input)?;
    let (input, value) = be_u8(input)?;
    Ok((input, Subpacket::TrustSignature(depth, value)))
}

// Parse a regular expression subpacket.
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.14
fn regular_expression(input: &[u8]) -> IResult<&[u8], Subpacket> {
    map(map(rest, read_string), Subpacket::RegularExpression).parse(input)
}

// Parse a revocation key subpacket
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.15
fn revocation_key(input: &[u8]) -> IResult<&[u8], Subpacket> {
    let (input, class) = map_opt(be_u8, RevocationKeyClass::from_u8).parse(input)?;
    let (input, algorithm) = map_opt(be_u8, PublicKeyAlgorithm::from_u8).parse(input)?;
    // TODO: V5 Keys have 32 octets here
    let (input, fp) = take(20usize)(input)?;
    Ok((
        input,
        Subpacket::RevocationKey(RevocationKey::new(class, algorithm, fp)),
    ))
}

// Parse a notation data subpacket
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.16
fn notation_data(input: &[u8]) -> IResult<&[u8], Subpacket> {
    // Flags
    let (input, readable) = map(be_u8, |v| v == 0x80).parse(input)?;
    let (input, _) = tag(&[0u8, 0, 0][..])(input)?;
    let (input, name_len) = be_u16(input)?;
    let (input, value_len) = be_u16(input)?;
    let (input, name) = map(take(name_len), read_string).parse(input)?;
    let (input, value) = map(take(value_len), read_string).parse(input)?;
    Ok((
        input,
        Subpacket::Notation(Notation {
            readable,
            name,
            value,
        }),
    ))
}

/// Parse a key server preferences subpacket
/// https://tools.ietf.org/html/rfc4880.html#section-5.2.3.17
fn key_server_prefs(body: &[u8]) -> IResult<&[u8], Subpacket> {
    Ok((
        &b""[..],
        Subpacket::KeyServerPreferences(SmallVec::from_slice(body)),
    ))
}

// Parse a preferred key server subpacket
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.18
fn preferred_key_server(input: &[u8]) -> IResult<&[u8], Subpacket> {
    let (input, body) = map_res(rest, str::from_utf8).parse(input)?;
    Ok((input, Subpacket::PreferredKeyServer(body.to_string())))
}

// Parse a primary user id subpacket
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.19
fn primary_userid(input: &[u8]) -> IResult<&[u8], Subpacket> {
    map(be_u8, |a| Subpacket::IsPrimary(a == 1)).parse(input)
}

// Parse a policy URI subpacket.
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.20
fn policy_uri(input: &[u8]) -> IResult<&[u8], Subpacket> {
    map(map(rest, read_string), Subpacket::PolicyURI).parse(input)
}

/// Parse a key flags subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.21
fn key_flags(body: &[u8]) -> IResult<&[u8], Subpacket> {
    Ok((&b""[..], Subpacket::KeyFlags(SmallVec::from_slice(body))))
}

// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.22
fn signers_userid(input: &[u8]) -> IResult<&[u8], Subpacket> {
    let (input, body) = map_res(rest, str::from_utf8).parse(input)?;
    Ok((input, Subpacket::SignersUserID(body.to_string())))
}

/// Parse a features subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.24
fn features(body: &[u8]) -> IResult<&[u8], Subpacket> {
    Ok((&b""[..], Subpacket::Features(SmallVec::from_slice(body))))
}

// Parse a revocation reason subpacket
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.23
fn rev_reason(input: &[u8]) -> IResult<&[u8], Subpacket> {
    let (input, code) = map_opt(be_u8, RevocationCode::from_u8).parse(input)?;
    let (input, reason) = map(rest, read_string).parse(input)?;
    Ok((input, Subpacket::RevocationReason(code, reason)))
}

// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.25
fn sig_target(input: &[u8]) -> IResult<&[u8], Subpacket> {
    let (input, pub_alg) = map_opt(be_u8, PublicKeyAlgorithm::from_u8).parse(input)?;
    let (input, hash_alg) = map_opt(be_u8, HashAlgorithm::from_u8).parse(input)?;
    let (input, hash) = rest(input)?;
    Ok((
        input,
        Subpacket::SignatureTarget(pub_alg, hash_alg, hash.to_vec()),
    ))
}

// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.26
fn embedded_sig(input: &[u8]) -> IResult<&[u8], Subpacket> {
    map(parse(Version::New), |sig| {
        Subpacket::EmbeddedSignature(Box::new(sig))
    }).parse(input)
}

// Parse an issuer subpacket
// Ref: https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-05#section-5.2.3.28
fn issuer_fingerprint(input: &[u8]) -> IResult<&[u8], Subpacket> {
    let (input, version) = map_opt(be_u8, KeyVersion::from_u8).parse(input)?;
    let (input, fingerprint) = rest(input)?;
    Ok((
        input,
        Subpacket::IssuerFingerprint(version, SmallVec::from_slice(fingerprint)),
    ))
}

/// Parse a preferred aead subpacket
fn pref_aead_alg(body: &[u8]) -> IResult<&[u8], Subpacket> {
    let list: SmallVec<[AeadAlgorithm; 2]> = body
        .iter()
        .map(|v| AeadAlgorithm::from_u8(*v).ok_or_else(|| format_err!("Invalid AeadAlgorithm")))
        .collect::<Result<_>>()?;

    Ok((&b""[..], Subpacket::PreferredAeadAlgorithms(list)))
}

fn subpacket(typ: SubpacketType, body: &[u8]) -> IResult<&[u8], Subpacket> {
    use self::SubpacketType::*;
    debug!("parsing subpacket: {:?} {}", typ, hex::encode(body));

    let res = match typ {
        SignatureCreationTime => signature_creation_time(body),
        SignatureExpirationTime => signature_expiration_time(body),
        ExportableCertification => exportable_certification(body),
        TrustSignature => trust_signature(body),
        RegularExpression => regular_expression(body),
        Revocable => revocable(body),
        KeyExpirationTime => key_expiration(body),
        PreferredSymmetricAlgorithms => pref_sym_alg(body),
        RevocationKey => revocation_key(body),
        Issuer => issuer(body),
        Notation => notation_data(body),
        PreferredHashAlgorithms => pref_hash_alg(body),
        PreferredCompressionAlgorithms => pref_com_alg(body),
        KeyServerPreferences => key_server_prefs(body),
        PreferredKeyServer => preferred_key_server(body),
        PrimaryUserId => primary_userid(body),
        PolicyURI => policy_uri(body),
        KeyFlags => key_flags(body),
        SignersUserID => signers_userid(body),
        RevocationReason => rev_reason(body),
        Features => features(body),
        SignatureTarget => sig_target(body),
        EmbeddedSignature => embedded_sig(body),
        IssuerFingerprint => issuer_fingerprint(body),
        PreferredAead => pref_aead_alg(body),
        Experimental(n) => Ok((body, Subpacket::Experimental(n, SmallVec::from_slice(body)))),
        Other(n) => Ok((body, Subpacket::Other(n, body.to_vec()))),
    };

    if res.is_err() {
        warn!("invalid subpacket: {:?} {:?}", typ, res);
    }

    res
}

fn subpackets(input: &[u8]) -> IResult<&[u8], Vec<Subpacket>> {
    many0(complete(|input| {
        // the subpacket length (1, 2, or 5 octets)
        let (input, len) = packet_length(input)?;
        // the subpacket type (1 octet)
        let (input, typ) = map_opt(be_u8, SubpacketType::from_u8).parse(input)?;
        let (input, body) = take(len - 1)(input)?;
        let (_, p) = subpacket(typ, body)?;
        Ok((input, p))
    })).parse(input)
}

fn actual_signature(typ: PublicKeyAlgorithm) -> impl Fn(&[u8]) -> IResult<&[u8], Vec<Mpi>> {
    move |input| match typ {
        PublicKeyAlgorithm::RSA | PublicKeyAlgorithm::RSASign => {
            map(mpi, |v| vec![v.to_owned()]).parse(input)
        }
        PublicKeyAlgorithm::DSA | PublicKeyAlgorithm::ECDSA | PublicKeyAlgorithm::EdDSA => {
            fold_many_m_n(
                2,
                2,
                mpi,
                Vec::new,
                |mut acc: Vec<Mpi>, item: MpiRef<'_>| {
                    acc.push(item.to_owned());
                    acc
                },
            ).parse(input)
        }
        PublicKeyAlgorithm::Private100
        | PublicKeyAlgorithm::Private101
        | PublicKeyAlgorithm::Private102
        | PublicKeyAlgorithm::Private103
        | PublicKeyAlgorithm::Private104
        | PublicKeyAlgorithm::Private105
        | PublicKeyAlgorithm::Private106
        | PublicKeyAlgorithm::Private107
        | PublicKeyAlgorithm::Private108
        | PublicKeyAlgorithm::Private109
        | PublicKeyAlgorithm::Private110 => map(mpi, |v| vec![v.to_owned()]).parse(input),
        _ => map(mpi, |v| vec![v.to_owned()]).parse(input),
    }
}

// Parse a v2 or v3 signature packet
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.2
fn v3_parser(
    packet_version: Version,
    version: SignatureVersion,
) -> impl Fn(&[u8]) -> IResult<&[u8], Signature> {
    move |input| {
        // One-octet length of following hashed material. MUST be 5.
        let (input, _) = tag(&[5u8][..])(input)?;
        // One-octet signature type.
        let (input, typ) = map_opt(be_u8, SignatureType::from_u8).parse(input)?;
        // Four-octet creation time.
        let (input, created) = map(be_u32, |v| Utc.timestamp_opt(i64::from(v), 0).unwrap()).parse(input)?;
        // Eight-octet Key ID of signer.
        let (input, issuer) = map_res(take(8usize), KeyId::from_slice).parse(input)?;
        // One-octet public-key algorithm.
        let (input, pub_alg) = map_opt(be_u8, PublicKeyAlgorithm::from_u8).parse(input)?;
        // One-octet hash algorithm.
        let (input, hash_alg) = map_opt(be_u8, HashAlgorithm::from_u8).parse(input)?;
        // Two-octet field holding left 16 bits of signed hash value.
        let (input, ls_hash) = take(2usize)(input)?;
        // One or more multiprecision integers comprising the signature.
        let (input, sig) = actual_signature(pub_alg)(input)?;

        let mut s = Signature::new(
            packet_version,
            version,
            typ,
            pub_alg,
            hash_alg,
            clone_into_array(ls_hash),
            sig,
            vec![],
            vec![],
        );

        s.config.created = Some(created);
        s.config.issuer = Some(issuer);

        Ok((input, s))
    }
}

// Parse a v4 or v5 signature packet
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3
fn v4_parser(
    packet_version: Version,
    version: SignatureVersion,
) -> impl Fn(&[u8]) -> IResult<&[u8], Signature> {
    move |input| {
        // One-octet signature type.
        let (input, typ) = map_opt(be_u8, SignatureType::from_u8).parse(input)?;
        // One-octet public-key algorithm.
        let (input, pub_alg) = map_opt(be_u8, PublicKeyAlgorithm::from_u8).parse(input)?;
        // One-octet hash algorithm.
        let (input, hash_alg) = map_opt(be_u8, HashAlgorithm::from_u8).parse(input)?;
        // Two-octet scalar octet count for following hashed subpacket data.
        let (input, hsub_len) = be_u16(input)?;
        // Hashed subpacket data set (zero or more subpackets).
        let (input, hsub_data) = take(hsub_len)(input)?;
        let (_, hsub) = subpackets(hsub_data)?;
        // Two-octet scalar octet count for the following unhashed subpacket data.
        let (input, usub_len) = be_u16(input)?;
        // Unhashed subpacket data set (zero or more subpackets).
        let (input, usub_data) = take(usub_len)(input)?;
        let (_, usub) = subpackets(usub_data)?;
        // Two-octet field holding the left 16 bits of the signed hash value.
        let (input, ls_hash) = take(2usize)(input)?;
        // One or more multiprecision integers comprising the signature.
        let (input, sig) = actual_signature(pub_alg)(input)?;

        Ok((
            input,
            Signature::new(
                packet_version,
                version,
                typ,
                pub_alg,
                hash_alg,
                clone_into_array(ls_hash),
                sig,
                hsub,
                usub,
            ),
        ))
    }
}

// Parse a signature packet (Tag 2)
// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2
fn parse(packet_version: Version) -> impl Fn(&[u8]) -> IResult<&[u8], Signature> {
    move |input| {
        let (input, version) = map_opt(be_u8, SignatureVersion::from_u8).parse(input)?;
        match version {
            SignatureVersion::V2 | SignatureVersion::V3 => {
                v3_parser(packet_version, version)(input)
            }
            SignatureVersion::V4 | SignatureVersion::V5 => {
                v4_parser(packet_version, version)(input)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subpacket_pref_sym_alg() {
        let input = vec![9, 8, 7, 3, 2];
        let (_, res) = pref_sym_alg(input.as_slice()).unwrap();
        assert_eq!(
            res,
            Subpacket::PreferredSymmetricAlgorithms(
                input
                    .iter()
                    .map(|i| SymmetricKeyAlgorithm::from_u8(*i).unwrap())
                    .collect()
            )
        );
    }
}
