use std::{fs::OpenOptions, io::Write};

use zeroize::Zeroize;

use crate::cli::CreateArgs;

/// Create a new encrypted file in the given path.
/// Do nothing and return error if the file already exists.
///
/// # Examples
/// ```no_run
/// create(CreateArgs { file: "example.encrypted".into() })?;
/// ```
pub fn create(args: &CreateArgs) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.file)?;
    write_header(&mut file)?;

    let mut password =
        rpassword::prompt_password("Create a password for the file: ")?;

    password.zeroize();

    todo!()
}

/// Write the header of the encrypted file.
fn write_header(writer: &mut impl Write) -> std::io::Result<()> {
    writer.write_all(b"0.1\nencrypted-file-format\n\n")?;
    writer.flush()?;
    Ok(())
}

/// Write the metadata section of the encrypted file.
fn write_metadata(
    writer: &mut impl Write,
    compression_enabled: bool,
    salt: &[u8; 32],
    nonce_dek: &[u8; 12],
    nonce_body: &[u8; 12],
    encrypted_dek: &[u8; 48],
) -> std::io::Result<()> {
    todo!()
}
