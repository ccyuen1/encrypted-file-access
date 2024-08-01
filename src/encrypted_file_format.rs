use std::ops::{Add, Sub};

use aead::{stream::StreamPrimitive, AeadInPlace, KeySizeUser};
use derive_where::derive_where;
use generic_array::{
    typenum::{operator_aliases::Sum, Unsigned},
    ArrayLength, GenericArray,
};
use serde::{Deserialize, Serialize};

// Default values for the header
pub const DEFAULT_FORMAT_VERSION: &str = "0.1";
pub const DEFAULT_FORMAT_MARKER: &str = "encrypted-file-access";
pub const DEFAULT_EXTENSION: &str = "txt";

// Constants for the metadata section
pub const SALT_SIZE: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Header of the encrypted file. See [`HeaderBuilder`] for building from default values.
pub struct Header<'a> {
    pub version: &'a str,
    pub format_marker: &'a str,
    pub extension: &'a str,
}

impl Default for Header<'_> {
    fn default() -> Self {
        Header {
            version: DEFAULT_FORMAT_VERSION,
            format_marker: DEFAULT_FORMAT_MARKER,
            extension: DEFAULT_EXTENSION,
        }
    }
}

#[derive(Debug, Clone, Default)]
/// Builder for the [`Header`] of the encrypted file.
pub struct HeaderBuilder<'a>(Header<'a>);

impl<'a> HeaderBuilder<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn version(mut self, version: &'a str) -> Self {
        self.0.version = version;
        self
    }

    pub fn format_marker(mut self, format_marker: &'a str) -> Self {
        self.0.format_marker = format_marker;
        self
    }

    pub fn extension(mut self, extension: &'a str) -> Self {
        self.0.extension = extension;
        self
    }

    pub fn build(self) -> Header<'a> {
        self.0
    }
}

#[derive_where(Debug, PartialEq, Eq)]
#[derive(Clone, Serialize, Deserialize)]
/// Metadata for the encrypted file
pub struct Metadata<A, S>
where
    A: AeadInPlace + KeySizeUser,
    S: StreamPrimitive<A>,
    A::NonceSize: Sub<S::NonceOverhead>,
    aead::stream::NonceSize<A, S>: ArrayLength<u8>,
    A::KeySize: Add<A::TagSize>,
    <A::KeySize as Add<A::TagSize>>::Output: ArrayLength<u8>,
{
    pub compression_enabled: bool,
    pub salt: [u8; SALT_SIZE],

    #[serde(bound(
        serialize = "aead::Nonce<A>: Serialize",
        deserialize = "aead::Nonce<A>: Deserialize<'de>"
    ))]
    pub nonce_dek: aead::Nonce<A>,

    #[serde(bound(
        serialize = "aead::stream::Nonce<A, S>: Serialize",
        deserialize = "aead::stream::Nonce<A, S>: Deserialize<'de>"
    ))]
    pub nonce_body: aead::stream::Nonce<A, S>,

    #[serde(bound(
        serialize = "GenericArray<u8, Sum<A::KeySize, A::TagSize>>: Serialize",
        deserialize = "GenericArray<u8, Sum<A::KeySize, A::TagSize>>: Deserialize<'de>"
    ))]
    pub encrypted_dek: GenericArray<u8, Sum<A::KeySize, A::TagSize>>,
}

impl<A, S> Metadata<A, S>
where
    A: AeadInPlace + KeySizeUser,
    S: StreamPrimitive<A>,
    A::NonceSize: Sub<S::NonceOverhead>,
    aead::stream::NonceSize<A, S>: ArrayLength<u8>,
    A::KeySize: Add<A::TagSize>,
    <A::KeySize as Add<A::TagSize>>::Output: ArrayLength<u8>,
{
    /// Memory size of the metadata in bytes
    pub const SIZE: usize = 1
        + SALT_SIZE
        + A::NonceSize::USIZE
        + aead::stream::NonceSize::<A, S>::USIZE
        + Sum::<A::KeySize, A::TagSize>::USIZE;
}

#[cfg(test)]
mod tests {
    use aead::stream::StreamBE32;
    use aes_gcm_siv::Aes256GcmSiv;

    use super::*;

    #[test]
    fn test_metadata_size() {
        assert_eq!(
            Metadata::<Aes256GcmSiv, StreamBE32<Aes256GcmSiv>>::SIZE,
            1 + SALT_SIZE + 12 + 7 + 48
        );
    }
}
