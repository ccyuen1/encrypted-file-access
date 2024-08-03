use std::ops::{Add, Sub};

use aead::{
    consts::{U1, U32},
    stream::StreamPrimitive,
    AeadInPlace, KeySizeUser,
};
use bytes::Bytes;
use derive_where::derive_where;
use either::Either::{self, Left, Right};
use generic_array::{
    typenum::{operator_aliases::Sum, Unsigned},
    ArrayLength, GenericArray,
};
use serde::{Deserialize, Serialize};

// Constants for the metadata section
pub type SaltSize = U32;
pub const SALT_SIZE: usize = SaltSize::USIZE;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Header of the encrypted file. See [`HeaderBuilder`] for building from default values.
pub struct Header {
    pub version: Bytes,
    pub format_marker: Bytes,
    pub extension: Bytes,
    pub xz_level: u32,
}

impl Header {
    /// Version of the encrypted file format
    pub const DEFAULT_VERSION: &'static str = "0.1.0";

    pub const DEFAULT_FORMAT_MARKER: &'static str = "encrypted-file-access";
    pub const DEFAULT_EXTENSION: &'static str = "txt";
    pub const DEFAULT_XZ_LEVEL: u32 = 6;
    pub const MAX_XZ_LEVEL: u32 = 9;
    pub const MIN_XZ_LEVEL: u32 = 0;
}

impl Default for Header {
    fn default() -> Self {
        Header {
            version: Bytes::from(Self::DEFAULT_VERSION),
            format_marker: Bytes::from(Self::DEFAULT_FORMAT_MARKER),
            extension: Bytes::from(Self::DEFAULT_EXTENSION),
            xz_level: Self::DEFAULT_XZ_LEVEL,
        }
    }
}

#[derive(Debug, Clone, Default)]
/// Builder for the [`Header`] of the encrypted file.
pub struct HeaderBuilder(Header);

impl HeaderBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn version(mut self, version: Either<String, &str>) -> Self {
        self.0.version = match version {
            Left(s) => Bytes::from(s),
            Right(s) => Bytes::copy_from_slice(s.as_bytes()),
        };
        self
    }

    pub fn format_marker(
        mut self,
        format_marker: Either<String, &str>,
    ) -> Self {
        self.0.format_marker = match format_marker {
            Left(s) => Bytes::from(s),
            Right(s) => Bytes::copy_from_slice(s.as_bytes()),
        };
        self
    }

    pub fn extension(mut self, extension: Either<String, &str>) -> Self {
        self.0.extension = match extension {
            Left(s) => Bytes::from(s),
            Right(s) => Bytes::copy_from_slice(s.as_bytes()),
        };
        self
    }

    pub fn xz_level(mut self, xz_level: u32) -> Self {
        self.0.xz_level = xz_level;
        self
    }

    pub fn build(self) -> Header {
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

/// Types which has a non-negative size.
pub trait SizeUser {
    type Size: ArrayLength<u8>;
}

impl<A, S> SizeUser for Metadata<A, S>
where
    A: AeadInPlace + KeySizeUser,
    S: StreamPrimitive<A>,
    A::NonceSize: Sub<S::NonceOverhead>,
    aead::stream::NonceSize<A, S>: ArrayLength<u8>,
    A::KeySize: Add<A::TagSize>,
    <A::KeySize as Add<A::TagSize>>::Output: ArrayLength<u8>,
    aead::stream::NonceSize<A, S>: Add<<A::KeySize as Add<A::TagSize>>::Output>,
    A::NonceSize:
        Add<Sum<aead::stream::NonceSize<A, S>, Sum<A::KeySize, A::TagSize>>>,
    SaltSize: Add<
        Sum<
            A::NonceSize,
            Sum<aead::stream::NonceSize<A, S>, Sum<A::KeySize, A::TagSize>>,
        >,
    >,
    U1: Add<
        Sum<
            SaltSize,
            Sum<
                A::NonceSize,
                Sum<aead::stream::NonceSize<A, S>, Sum<A::KeySize, A::TagSize>>,
            >,
        >,
    >,
    Sum<
        U1,
        Sum<
            SaltSize,
            Sum<
                A::NonceSize,
                Sum<aead::stream::NonceSize<A, S>, Sum<A::KeySize, A::TagSize>>,
            >,
        >,
    >: ArrayLength<u8>,
{
    type Size = Sum<
        U1,
        Sum<
            SaltSize,
            Sum<
                A::NonceSize,
                Sum<aead::stream::NonceSize<A, S>, Sum<A::KeySize, A::TagSize>>,
            >,
        >,
    >;
}

#[cfg(test)]
mod tests {
    use aead::stream::StreamBE32;
    use aes_gcm_siv::Aes256GcmSiv;

    use super::*;

    #[test]
    fn test_metadata_size() {
        assert_eq!(
            <Metadata::<Aes256GcmSiv, StreamBE32<_>> as SizeUser>::Size::USIZE,
            1 + SALT_SIZE + 12 + 7 + 48
        );
    }
}
