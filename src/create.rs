use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    path::PathBuf,
};

use aes_gcm_siv::{aead::Aead, Aes256GcmSiv, Key, KeyInit, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use clap::Args;
use rand::{Rng, SeedableRng};
use zeroize::Zeroize;

use crate::encrypted_file_format::{Header, Metadata};

#[derive(Args, Debug)]
/// Arguments for creating a new encrypted file
pub struct CreateArgs {
    /// Path to the encrypted file to create
    pub out_file: PathBuf,

    #[arg(short, long)]
    /// Path to the plaintext file to be encrypted. If missing, an empty file is created
    pub src: Option<PathBuf>,

    #[arg(short, long)]
    /// Extension for the decrypted file. Overwitten by extension of src if provided. Default to txt
    pub extension: Option<String>,

    #[arg(long)]
    /// If given, the plaintext file is not compressed before encryption
    pub no_compress: bool,

    #[arg(short, long)]
    /// If given, it is between 0-9 (inclusive). Ignored when --no-compress is given. Default to 6
    pub xz_preset: Option<u32>,
}

/// Create a new encrypted file in the given path.
/// Do nothing and return error if the file already exists.
///
/// # Panics
/// Panics if `getrandom` is unable to provide secure entropy.  
/// Panics if unable to hash the password or encrypt the data.
///
/// # Examples
/// ```no_run
/// create(&CreateArgs {
///    file: "example.encrypted".into(),
///    src: None,
///    extension: Some("txt".to_string()),
///    no_compress: true,
///    })?;
/// ```
pub fn create(args: &CreateArgs) -> Result<(), Box<dyn std::error::Error>> {
    // check if the source file exists
    if let Some(src) = args.src.as_ref() {
        if !src.try_exists()? {
            return Err("Source file does not exist".into());
        }
    }
    // open the output file
    let mut out_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.out_file)?;

    // write the header to the file
    write_header(&mut out_file, args)?;

    // generate random numbers that will be stored in plaintext
    let mut rng = rand::rngs::StdRng::from_entropy();
    let salt: [u8; 32] = rng.gen();
    let nonce_dek = Nonce::from(rng.gen::<[u8; 12]>());
    let nonce_body = rng.gen::<[u8; 12]>();

    // derive the key encryption key (KEK)
    let kek = prompt_for_password_and_derive_kek(&salt)?;

    // generate the data encryption key (DEK)
    let dek = Key::<Aes256GcmSiv>::from(rng.gen::<[u8; 32]>());

    // encrypt the DEK using KEK
    let cipher = Aes256GcmSiv::new(&kek);
    let encrypted_dek = cipher
        .encrypt(&nonce_dek, dek.as_ref())?
        .try_into()
        .expect("The encrypted data encryption key should be 48 bytes long");

    // write the metadata section to the file
    let md = Metadata {
        compression_enabled: !args.no_compress,
        salt,
        nonce_dek: nonce_dek.into(),
        nonce_body,
        encrypted_dek,
    };
    write_metadata(&mut out_file, &md)?;

    // TODO: encrypt the file content and store to output file
    let cipher = Aes256GcmSiv::new(&dek);

    out_file.flush()?;

    // TODO: verify the integrity of the encrypted file

    todo!()
}

/// Write the header of the encrypted file.
fn write_header(
    writer: &mut impl io::Write,
    header: &Header,
) -> io::Result<()> {
    writeln!(writer, "{}", header.version)?;
    writeln!(writer, "{}", header.format_marker)?;
    writeln!(writer, "{}", header.extension)?;
    writer.write_all(b"\n")?;
    Ok(())
}

/// Write the metadata section to the writer.
fn write_metadata(
    writer: &mut impl io::Write,
    md: &Metadata,
) -> io::Result<()> {
    // mark that plaintext file is compressed before encryption or not
    if md.compression_enabled {
        writer.write_all(&[1u8])?;
    } else {
        writer.write_all(&[0u8])?;
    }

    writer.write_all(&md.salt)?;
    writer.write_all(&md.nonce_dek)?;
    writer.write_all(&md.nonce_body)?;
    writer.write_all(&md.encrypted_dek)?;

    Ok(())
}

/// Prompt the user for a password and derive the key encryption key (KEK) using Argon2id.
fn prompt_for_password_and_derive_kek(
    salt: &[u8],
) -> Result<Key<Aes256GcmSiv>, Box<dyn std::error::Error>> {
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(19_456u32, 2u32, 1u32, Some(32usize))
            .expect("Failed to create Argon2 params"),
    );

    // create a KEK buffer
    let mut kek = Key::<Aes256GcmSiv>::from([0u8; 32]);

    let mut password =
        rpassword::prompt_password("Create a password for the file: ")?;

    // hash the password using Argon2id to obtain the KEK
    argon2.hash_password_into(password.as_bytes(), salt, kek.as_mut_slice())?;

    // make best effort to prevent leak
    password.zeroize();

    Ok(kek)
}
