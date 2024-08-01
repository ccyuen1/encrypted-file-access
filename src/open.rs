use std::{
    fs::File,
    io::{self, BufRead},
    ops::{Add, Sub},
    path::PathBuf,
};

use aead::{
    stream::{StreamBE32, StreamPrimitive},
    AeadInPlace, KeySizeUser,
};
use aes_gcm_siv::Aes256GcmSiv;
use anyhow::anyhow;
use clap::Args;
use generic_array::ArrayLength;
use open::commands;

use crate::{
    config::{csv_reader_builder, MAX_HEADER_SIZE},
    encrypted_file_format::{Header, Metadata},
};

#[derive(Args, Debug)]
/// Arguments for opening an existing encrypted file
pub struct OpenArgs {
    /// Path to the encrypted file to open
    pub file: PathBuf,

    #[arg(short, long)]
    /// Executable to open the decrypted file. If not given, use the default system handler
    pub executable: Option<PathBuf>,
}

/// Decrypt a password-protected file to a temporary file
/// and then open it with the specified application.
///
/// Modifications to the temporary file are reflected in the password-protected file
/// after the application terminates.
///
/// # Examples
/// ```no_run
/// use std::path::PathBuf;
/// use encrypted_file_access::open::{OpenArgs, open};
/// let args = OpenArgs {
///     file: PathBuf::from("example.encrypted"),
///     executable: Some(PathBuf::from("notepad.exe")),
/// };
/// open(&args).unwrap();
/// ```
pub fn open(args: &OpenArgs) -> anyhow::Result<()> {
    let mut in_file = File::open(&args.file)?;
    let header = read_header(&mut in_file)?;
    let metadata: Metadata<Aes256GcmSiv, StreamBE32<_>> =
        read_metadata(&mut in_file)?;

    // TODO: prepare a temporary file

    // TODO: decrypt the body

    // TODO: open the decrypted file with the specified application

    // TODO: after the application terminates,
    //       create a new password-protected file alongside the original file
    //       reflecting the modifications made to the temporary file

    // TODO: clean up the temporary file safely with best effort

    // TODO: replace the original file with the new file

    todo!()
}

/// Read and parse the header of an encrypted file.
/// This will error if the header is invalid.
fn read_header<R: BufRead>(reader: R) -> csv::Result<(Header, R)> {
    // Read the byte array of the header.
    // This is to ensure that the CSV reader cannot read past the end of the header.
    let mut take_reader = reader.take(MAX_HEADER_SIZE);
    let mut buf = Vec::new();
    take_reader.read_until(b'\n', &mut buf)?;
    match buf.last() {
        Some(b'\n') => (),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Header does not end with line feed or too large",
            )
            .into());
        }
    }

    // parse the header
    let header: Header = csv_reader_builder()
        .from_reader(buf.as_slice())
        .deserialize()
        .next()
        .ok_or(io::Error::from(io::ErrorKind::InvalidData))??;

    Ok((header, take_reader.into_inner()))
}

/// Read and parse the metadata section of an encrypted file.
///
/// This will error if the metadata section is invalid.
fn read_metadata<A, S>(
    reader: &mut impl io::Read,
) -> anyhow::Result<Metadata<A, S>>
where
    A: AeadInPlace + KeySizeUser,
    S: StreamPrimitive<A>,
    A::NonceSize: Sub<S::NonceOverhead>,
    aead::stream::NonceSize<A, S>: ArrayLength<u8>,
    A::KeySize: Add<A::TagSize>,
    <A::KeySize as Add<A::TagSize>>::Output: ArrayLength<u8>,
{
    todo!()
}
