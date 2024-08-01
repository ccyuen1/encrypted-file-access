use std::{
    fs::File,
    io,
    ops::{Add, Sub},
    path::PathBuf,
};

use aead::{
    stream::{StreamBE32, StreamPrimitive},
    AeadInPlace, KeySizeUser,
};
use aes_gcm_siv::Aes256GcmSiv;
use clap::Args;
use generic_array::ArrayLength;
use open::commands;

use crate::encrypted_file_format::{Header, Metadata};

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
///
/// This will error if the header is invalid.
fn read_header(reader: &mut impl io::Read) -> anyhow::Result<Header> {
    todo!()
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
