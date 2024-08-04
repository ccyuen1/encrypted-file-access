use std::{fs::File, io, path::PathBuf};

use aead::stream::StreamBE32;
use aes_gcm_siv::Aes256GcmSiv;
use clap::Args;
use secrecy::Secret;

use crate::{
    encrypted_file_format::Metadata,
    encryption::prompt_for_password,
    open::{
        create_encrypted_file_alongside_path, decrypt_to_temp_file,
        fill_file_with_zeros, read_header, read_metadata,
    },
};

#[derive(Args, Debug)]
/// Arguments for changing the password of a password-protected file
pub struct ChangePasswordArgs {
    /// Path to the encrypted file
    pub file: PathBuf,

    /// Disable or enable compression if provided
    pub no_compress: Option<bool>,

    /// New XZ compression level (0-9), ignored if compression is disabled
    pub xz_level: Option<u32>,
}

/// Change the password of a password-protected file.
///
/// If the old and/or new password are not provided,
/// the user will be prompted to enter them.
///
/// # Panics
/// Panics if `getrandom` is unable to provide secure entropy to re-encrypt the file.
///
/// # Examples
/// ```no_run
/// use std::path::PathBuf;
/// use encrypted_file_access::change_password::{ChangePasswordArgs, change_password};
/// let args = ChangePasswordArgs {
///     file: PathBuf::from("example.encrypted"),
///     no_compress: None,
///     xz_level: None,
/// };
/// change_password(&args, None, None).unwrap();
/// // User will be prompted to enter old and new passwords
/// ```
pub fn change_password(
    args: &ChangePasswordArgs,
    old_password: Option<Secret<String>>,
    new_password: Option<Secret<String>>,
) -> anyhow::Result<()> {
    // prompt for passwords if not provided
    let old_password = if let Some(pw) = old_password {
        pw
    } else {
        prompt_for_password(false)?
    };
    let new_password = if let Some(pw) = new_password {
        pw
    } else {
        prompt_for_password(true)?
    };

    // read file and decrypt it to a temporary file
    let mut in_reader = io::BufReader::new(File::open(&args.file)?);
    let header = read_header(&mut in_reader)?;
    let metadata: Metadata<Aes256GcmSiv, StreamBE32<_>> =
        read_metadata(&mut in_reader)?;
    let (temp_dir, decrypted_file_path) =
        decrypt_to_temp_file(in_reader, &header, &metadata, &old_password)?;
    drop(old_password); // done with old password

    let new_file_path = create_encrypted_file_alongside_path(
        &args.file,
        decrypted_file_path.clone(),
        args.no_compress.unwrap_or(!metadata.compression_enabled),
        args.xz_level.unwrap_or(header.xz_level),
        Some(new_password),
    )?;

    // replace the original file with the new file
    std::fs::rename(&new_file_path, &args.file)?;

    // clean up the temporary file with best effort
    if let Err(e) = fill_file_with_zeros(&decrypted_file_path) {
        eprintln!(
            "Failed to fill the temporary file with zeros before deleting the it: {}", e
        );
    }
    temp_dir.close()?;

    Ok(())
}
