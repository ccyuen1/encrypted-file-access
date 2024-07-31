// Default values for the header
pub const DEFAULT_FORMAT_VERSION: &str = "0.1";
pub const DEFAULT_FORMAT_MARKER: &str = "encrypted-file-access";
pub const DEFAULT_EXTENSION: &str = "txt";

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Metadata for the encrypted file
pub struct Metadata {
    pub compression_enabled: bool,
    pub salt: [u8; 32],
    pub nonce_dek: [u8; 12],
    pub nonce_body: [u8; 7],

    #[serde(with = "BigArray")]
    pub encrypted_dek: [u8; 48],
}

impl Metadata {
    /// Memory size of the metadata in bytes
    pub const SIZE: usize = 1 + 32 + 12 + 7 + 48;
}
