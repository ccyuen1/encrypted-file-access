// Default values for the header
const DEFAULT_FORMAT_VERSION: &str = "0.1";
const DEFAULT_FORMAT_MARKER: &str = "encrypted-file-access";
const DEFAULT_EXTENSION: &str = "txt";

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Header of the encrypted file
pub struct Header<'a> {
    pub version: &'a str,
    pub format_marker: &'a str,
    pub extension: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Metadata for the encrypted file
pub struct Metadata {
    pub compression_enabled: bool,
    pub salt: [u8; 32],
    pub nonce_dek: [u8; 12],
    pub nonce_body: [u8; 12],

    #[serde(with = "BigArray")]
    pub encrypted_dek: [u8; 48],
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
