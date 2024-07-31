use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    path::PathBuf,
};

use aes_gcm_siv::{
    aead::{stream::EncryptorBE32, Aead as _},
    Aes256GcmSiv, Key, KeyInit, Nonce,
};
use anyhow::{anyhow, bail};
use clap::Args;
use either::Either::{Left, Right};
use rand::{Rng as _, SeedableRng as _};
use xz2::bufread::XzEncoder;
use zeroize::Zeroize as _;

use crate::{
    config::{
        argon2_config, csv_writer_builder, DEFAULT_DECRYPTED_FILE_EXTENSION,
    },
    encrypted_file_format::{Header, HeaderBuilder, Metadata},
};

#[derive(Args, Debug)]
/// Arguments for creating a new encrypted file
pub struct CreateArgs {
    /// Path to the encrypted file to create
    pub out_file: PathBuf,

    #[arg(short, long)]
    /// Path to the plaintext file to be encrypted. If missing, an empty file is created
    pub src: Option<PathBuf>,

    #[arg(short, long)]
    /// Extension for the decrypted file. Overwritten by extension of src if provided. Default: txt
    pub extension: Option<String>,

    #[arg(long)]
    /// If given, the plaintext file is not compressed before encryption
    pub no_compress: bool,

    #[arg(long, default_value_t = 6, value_parser = clap::value_parser!(u32).range(0..=9))]
    /// Compression level of XZ algorithm. Valid values are 0-9. Ignored when --no-compress is given.
    pub xz_level: u32,
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
pub fn create(args: &CreateArgs) -> anyhow::Result<()> {
    // check if the source file exists
    if let Some(src) = args.src.as_ref() {
        if !src.try_exists()? {
            bail!("Source file does not exist");
        }
    }
    // open the output file
    let mut out_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.out_file)?;

    // write the header to the file
    let mut header_builder = HeaderBuilder::new();
    header_builder = header_builder.extension(get_extension(args)?);
    let header = header_builder.build();
    write_header(&mut out_file, &header)?;

    // generate random numbers that will be stored in plaintext
    let mut rng = rand::rngs::StdRng::from_entropy();
    let salt: [u8; 32] = rng.gen();
    let nonce_dek = Nonce::from(rng.gen::<[u8; 12]>());
    let nonce_body = rng.gen();

    // derive the key encryption key (KEK)
    let mut kek = prompt_for_password_and_derive_kek(&salt)?;

    // generate the data encryption key (DEK)
    let mut dek = Key::<Aes256GcmSiv>::from(rng.gen::<[u8; 32]>());

    // encrypt the DEK using KEK
    let cipher = Aes256GcmSiv::new(&kek);
    kek.zeroize(); // done with KEK
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

    if let Some(src) = args.src.as_ref() {
        // prepare for the file body encryption
        let encryptor: EncryptorBE32<Aes256GcmSiv> =
            EncryptorBE32::new(&dek, &nonce_body.into());
        dek.zeroize(); // done with DEK

        // get handler of the source file if specified
        let reader = io::BufReader::new(File::open(src)?);

        // compress the file body if compression is enabled
        let mut reader = if !args.no_compress {
            Left(XzEncoder::new(reader, args.xz_level))
        } else {
            Right(reader)
        };

        crate::encryption::stream_encrypt(
            encryptor,
            &mut reader,
            &mut out_file,
        )?;
    }
    out_file.flush()?;

    Ok(())
}

/// Write the header of the encrypted file.
fn write_header(
    writer: &mut impl io::Write,
    header: &Header,
) -> csv::Result<()> {
    csv_writer_builder().from_writer(writer).serialize(header)
}

/// Write the metadata section to the writer.
fn write_metadata(
    writer: &mut impl io::Write,
    md: &Metadata,
) -> bincode::Result<()> {
    bincode::serialize_into(writer, md)
}

/// Prompt the user for a password and derive the key encryption key (KEK) using Argon2id.
fn prompt_for_password_and_derive_kek(
    salt: &[u8],
) -> anyhow::Result<Key<Aes256GcmSiv>> {
    let argon2 = argon2_config();

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

/// Extract the correct file extension from the command line arguments.  
/// If not provided, [`DEFAULT_DECRYPTED_FILE_EXTENSION`] is returned.
fn get_extension(args: &CreateArgs) -> anyhow::Result<&str> {
    if let Some(src) = &args.src {
        let ext = src
            .extension()
            .map(|e| {
                e.to_str()
                    .ok_or(anyhow!("Source extension is not valid Unicode"))
            })
            .transpose()?;
        if let Some(e) = ext {
            return Ok(e);
        }
    }
    Ok(args
        .extension
        .as_deref()
        .unwrap_or(DEFAULT_DECRYPTED_FILE_EXTENSION))
}

#[cfg(test)]
mod tests {

    use crate::encrypted_file_format::{
        DEFAULT_EXTENSION, DEFAULT_FORMAT_MARKER, DEFAULT_FORMAT_VERSION,
    };

    use super::*;

    #[test]
    fn test_write_header() {
        let header = Header::default();
        let mut buf = Vec::new();
        write_header(&mut buf, &header).unwrap();
        let expected_csv = format!(
            "{},{},{}\n",
            DEFAULT_FORMAT_VERSION, DEFAULT_FORMAT_MARKER, DEFAULT_EXTENSION
        );
        assert_eq!(buf, expected_csv.as_bytes());
    }

    #[test]
    fn test_write_metadata() {
        let mut rng = rand::thread_rng();
        for _ in 0..3 {
            let md = Metadata {
                compression_enabled: rng.gen(),
                salt: rng.gen(),
                nonce_dek: rng.gen(),
                nonce_body: rng.gen(),
                encrypted_dek: core::array::from_fn(|_| rng.gen()),
            };
            let mut buf = Vec::new();
            write_metadata(&mut buf, &md).unwrap();
            assert_eq!(buf.len(), Metadata::SIZE);
            assert_eq!(bincode::deserialize::<Metadata>(&buf).unwrap(), md);
        }
    }
}
