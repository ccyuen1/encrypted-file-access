use aes_gcm_siv::{
    aead::generic_array::typenum::Unsigned, AeadCore, Aes256GcmSiv,
};
use argon2::{Algorithm, Argon2, Params, Version};

// Constants
//
/// Buffer size for AEAD stream encryption.
/// This is a fixed value so that it is known during decryption.
pub const AEAD_STREAM_ENCRYPTION_BUFFER_LENGTH: usize = 1024 * 1024; // 1MB

/// Tag size for AES256-GCM-SIV.
pub const AES256GCMSIV_TAG_SIZE: usize =
    <Aes256GcmSiv as AeadCore>::TagSize::USIZE;

/// Buffer size for AES256-GCM-SIV stream decryption.
pub const AES256GCMSIV_DECRYPTION_BUFFER_LENGTH: usize =
    AEAD_STREAM_ENCRYPTION_BUFFER_LENGTH + AES256GCMSIV_TAG_SIZE;

/// Default file extension for the decrypted file.
pub const DEFAULT_DECRYPTED_FILE_EXTENSION: &str = "txt";
//
//

/// Create a default Argon2 instance for our use.
pub fn argon2_config() -> Argon2<'static> {
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(19_456u32, 2u32, 1u32, Some(32usize))
            .expect("Failed to create Argon2 params"),
    )
}

/// Create a default [`csv::WriterBuilder`] for our use.
pub fn csv_writer_builder() -> csv::WriterBuilder {
    let mut builder = csv::WriterBuilder::new();
    builder
        .has_headers(false)
        .delimiter(b',')
        .terminator(csv::Terminator::Any(b'\n'))
        .quote_style(csv::QuoteStyle::Necessary);
    builder
}
