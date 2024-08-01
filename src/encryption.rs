use std::io;

use aes_gcm_siv::{
    aead::stream::{DecryptorBE32, EncryptorBE32},
    Aes256GcmSiv,
};
use anyhow::{bail, Context};

use crate::config::{
    AEAD_STREAM_ENCRYPTION_BUFFER_LENGTH, AES256GCMSIV_TAG_SIZE,
};

/// Encrypt the content from the reader and write to the writer.  
/// If error is encounted, the status of the reader and writer are undefined.
pub fn stream_encrypt(
    mut encryptor: EncryptorBE32<Aes256GcmSiv>,
    reader: &mut impl io::Read,
    writer: &mut impl io::Write,
) -> anyhow::Result<()> {
    const BUFFER_LEN: usize = AEAD_STREAM_ENCRYPTION_BUFFER_LENGTH;

    // for Aes256, need to change it if other AEAD primitive is used
    const TAG_SIZE: usize = AES256GCMSIV_TAG_SIZE;

    let mut in_buffer = vec![0u8; BUFFER_LEN];
    let mut total_read_len_in_iter;
    loop {
        total_read_len_in_iter = 0;
        let mut one_time_read_len = reader.read(&mut in_buffer)?;
        total_read_len_in_iter += one_time_read_len;
        while one_time_read_len > 0 && total_read_len_in_iter < BUFFER_LEN {
            one_time_read_len =
                reader.read(&mut in_buffer[total_read_len_in_iter..])?;
            total_read_len_in_iter += one_time_read_len;
        }
        if total_read_len_in_iter < BUFFER_LEN {
            // last chunk
            break;
        }

        let ciphertext = encryptor
            .encrypt_next(in_buffer.as_slice())
            .with_context(|| "Failed to encrypt file body")?;

        // check the length of the ciphertext
        if ciphertext.len() != BUFFER_LEN + TAG_SIZE {
            bail!(
                "Unexpected ciphertext chunk with length {}, expected {}",
                ciphertext.len(),
                BUFFER_LEN + TAG_SIZE
            );
        }

        writer.write_all(&ciphertext)?;
    }

    // last chunk of data needs a different method
    let ciphertext = encryptor
        .encrypt_last(&in_buffer[..total_read_len_in_iter])
        .with_context(|| "Failed to encrypt last chunk of file body")?;
    // check the length of the ciphertext
    if ciphertext.len() != total_read_len_in_iter + TAG_SIZE {
        bail!(
            "Unexpected ciphertext chunk with length {}, expected {}",
            ciphertext.len(),
            BUFFER_LEN + TAG_SIZE
        );
    }
    writer.write_all(&ciphertext)?;

    Ok(())
}

/// Decrypt the content from the reader and write to the writer.  
/// If error is encounted, the status of the reader and writer are undefined.
pub fn stream_decrypt(
    mut decryptor: DecryptorBE32<Aes256GcmSiv>,
    reader: &mut impl io::Read,
    writer: &mut impl io::Write,
) -> anyhow::Result<()> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_encrypt_decrypt() {
        let plaintext = "savuduasb v\u{2144} ua cab2 cuancnacungyeucgnau";
        let key = b"qwertyuiopasdfghjklzxcvbnmasdfgh";
        let nonce = b"asithyd";
        let encryptor: EncryptorBE32<Aes256GcmSiv> =
            EncryptorBE32::new(key.into(), nonce.into());
        let decryptor: DecryptorBE32<Aes256GcmSiv> =
            DecryptorBE32::new(key.into(), nonce.into());
        let mut encrypted = Vec::new();
        stream_encrypt(encryptor, &mut plaintext.as_bytes(), &mut encrypted)
            .unwrap();
        let mut decrypted = Vec::new();
        stream_decrypt(decryptor, &mut encrypted.as_slice(), &mut decrypted)
            .unwrap();
        assert_eq!(plaintext.as_bytes(), decrypted);
    }
}
