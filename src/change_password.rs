use std::path::PathBuf;

use clap::Args;
use secrecy::Secret;

#[derive(Args, Debug)]
/// Arguments for changing the password of a password-protected file
pub struct ChangePasswordArgs {
    /// Path to the encrypted file
    pub file: PathBuf,

    /// Disable compression
    pub no_compress: bool,

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
/// let args = ChangePasswordArgs { file: PathBuf::from("example.encrypted") };
/// change_password(&args, None, None).unwrap();
/// // User will be prompted to enter old and new passwords
/// ```
pub fn change_password(
    args: &ChangePasswordArgs,
    old_pw: Option<Secret<String>>,
    new_pw: Option<Secret<String>>,
) -> anyhow::Result<()> {
    todo!()
}
