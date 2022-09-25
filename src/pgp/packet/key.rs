impl_public_key!(PublicKey, crate::pgp::types::Tag::PublicKey);
impl_public_key!(PublicSubkey, crate::pgp::types::Tag::PublicSubkey);

impl_secret_key!(SecretKey, crate::pgp::types::Tag::SecretKey, PublicKey);
impl_secret_key!(
    SecretSubkey,
    crate::pgp::types::Tag::SecretSubkey,
    PublicSubkey
);
