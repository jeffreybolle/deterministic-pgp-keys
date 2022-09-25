//! Deserialize trait

use crate::pgp::errors::Result;
use crate::pgp::types::Version;

pub trait Deserialize: Sized {
    fn from_slice(_: Version, _: &[u8]) -> Result<Self>;
}
