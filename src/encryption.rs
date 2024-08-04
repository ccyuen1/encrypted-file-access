use std::io;

use aead::Key;
use aes_gcm_siv::{
    aead::stream::{DecryptorBE32, EncryptorBE32},
    Aes256GcmSiv,
};
use anyhow::{bail, Context};
use secrecy::{ExposeSecret, Secret};

use crate::config::{
    argon2_config, AEAD_STREAM_ENCRYPTION_BUFFER_LENGTH, AES256GCMSIV_TAG_SIZE,
};

/// Prompt the user for a password.
/// Parameter `create` indicates whether a new password is being created or not.
pub fn prompt_for_password(create: bool) -> anyhow::Result<Secret<String>> {
    let message = if create {
        "Create a password for the file: "
    } else {
        "Enter the existing password for the file: "
    };
    Ok(Secret::new(rpassword::prompt_password(message)?))
}

/// Encrypt the content from the reader and write to the writer.  
/// If error is encounted, the state of the reader and writer are unspecified.
pub fn stream_encrypt(
    mut encryptor: EncryptorBE32<Aes256GcmSiv>,
    reader: &mut impl io::Read,
    writer: &mut impl io::Write,
) -> anyhow::Result<()> {
    const BUFFER_LEN: usize = AEAD_STREAM_ENCRYPTION_BUFFER_LENGTH;

    // This is for Aes256. Need to change it if other AEAD primitive is used
    const TAG_SIZE: usize = AES256GCMSIV_TAG_SIZE;

    let mut in_buffer = vec![0u8; BUFFER_LEN];
    let mut total_read_len_in_one_loop;
    loop {
        total_read_len_in_one_loop = 0;
        let mut one_time_read_len = reader.read(&mut in_buffer)?;
        total_read_len_in_one_loop += one_time_read_len;
        while one_time_read_len > 0 && total_read_len_in_one_loop < BUFFER_LEN {
            one_time_read_len =
                reader.read(&mut in_buffer[total_read_len_in_one_loop..])?;
            total_read_len_in_one_loop += one_time_read_len;
        }
        if total_read_len_in_one_loop < BUFFER_LEN {
            // last chunk
            break;
        }

        let ciphertext = encryptor
            .encrypt_next(in_buffer.as_slice())
            .with_context(|| "Failed to encrypt from reader")?;

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
        .encrypt_last(&in_buffer[..total_read_len_in_one_loop])
        .with_context(|| "Failed to encrypt last chunk from reader")?;
    // check the length of the ciphertext
    if ciphertext.len() != total_read_len_in_one_loop + TAG_SIZE {
        bail!(
            "Unexpected ciphertext chunk with length {}, expected {}",
            ciphertext.len(),
            total_read_len_in_one_loop + TAG_SIZE
        );
    }
    writer.write_all(&ciphertext)?;

    Ok(())
}

/// Decrypt the content from the reader and write to the writer
/// using AES-GCM-SIV with 256-bit key.  
/// If error is encounted, the state of the reader and writer are unspecified.
pub fn stream_decrypt(
    mut decryptor: DecryptorBE32<Aes256GcmSiv>,
    reader: &mut impl io::Read,
    writer: &mut impl io::Write,
) -> anyhow::Result<()> {
    // This is for Aes256. Need to change it if other AEAD primitive is used
    const TAG_SIZE: usize = AES256GCMSIV_TAG_SIZE;

    const BUFFER_LEN: usize = AEAD_STREAM_ENCRYPTION_BUFFER_LENGTH + TAG_SIZE;

    let mut buf = vec![0u8; BUFFER_LEN];
    let mut total_read_len_in_one_loop;
    loop {
        total_read_len_in_one_loop = 0;
        let mut one_time_read_len = reader.read(&mut buf)?;
        total_read_len_in_one_loop += one_time_read_len;
        while one_time_read_len > 0 && total_read_len_in_one_loop < BUFFER_LEN {
            one_time_read_len =
                reader.read(&mut buf[total_read_len_in_one_loop..])?;
            total_read_len_in_one_loop += one_time_read_len;
        }
        if total_read_len_in_one_loop < BUFFER_LEN {
            // last chunk
            break;
        }

        let plaintest = decryptor
            .decrypt_next(buf.as_slice())
            .with_context(|| "Failed to decrypt from reader")?;

        // check the length of the plaintext
        if plaintest.len() != BUFFER_LEN - TAG_SIZE {
            bail!(
                "Unexpected ciphertext chunk with length {}, expected {}",
                plaintest.len(),
                BUFFER_LEN - TAG_SIZE
            );
        }

        writer.write_all(&plaintest)?;
    }

    // last chunk of data needs a different method
    let plaintext = decryptor
        .decrypt_last(&buf[..total_read_len_in_one_loop])
        .with_context(|| "Failed to decrypt last chunk from reader")?;
    // check the length of the plaintext
    if plaintext.len() + TAG_SIZE != total_read_len_in_one_loop {
        bail!(
            "Unexpected plaintext chunk with length {}, expected {}",
            plaintext.len(),
            total_read_len_in_one_loop - TAG_SIZE
        );
    }
    writer.write_all(&plaintext)?;

    Ok(())
}

/// Derive the key encryption key (KEK) using Argon2id.
pub fn derive_kek(
    password: &Secret<String>,
    salt: &[u8],
) -> argon2::Result<Secret<Key<Aes256GcmSiv>>> {
    let argon2 = argon2_config();

    // create a KEK buffer
    let mut kek = Key::<Aes256GcmSiv>::from([0u8; 32]);

    // hash the password using Argon2id to obtain the KEK
    argon2.hash_password_into(
        password.expose_secret().as_bytes(),
        salt,
        kek.as_mut_slice(),
    )?;

    Ok(Secret::new(kek))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_encrypt_decrypt_small() {
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

    #[test]
    fn test_stream_encrypt_decrypt_large() {
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let plaintext: Vec<u8> = std::iter::from_fn(|| Some(rng.gen::<u8>()))
            .take(1024 * 1024 * 5)
            .collect();
        let key = b"qwertyuiopasdfghjklzxcvbnmasdfgh";
        let nonce = b"asithyd";
        let encryptor: EncryptorBE32<Aes256GcmSiv> =
            EncryptorBE32::new(key.into(), nonce.into());
        let decryptor: DecryptorBE32<Aes256GcmSiv> =
            DecryptorBE32::new(key.into(), nonce.into());
        let mut encrypted = Vec::new();
        stream_encrypt(encryptor, &mut plaintext.as_slice(), &mut encrypted)
            .unwrap();
        let mut decrypted = Vec::new();
        stream_decrypt(decryptor, &mut encrypted.as_slice(), &mut decrypted)
            .unwrap();
        assert_eq!(plaintext, decrypted);
    }
}
