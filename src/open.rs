use std::{
    fs::File,
    io::{self, BufRead},
    ops::{Add, Sub},
    path::PathBuf,
};

use aead::{
    consts::U1,
    stream::{StreamBE32, StreamPrimitive},
    AeadInPlace, KeySizeUser,
};
use aes_gcm_siv::Aes256GcmSiv;
use clap::Args;
use generic_array::{typenum::Sum, ArrayLength, GenericArray};
use open::commands;

use crate::{
    config::{csv_reader_builder, MAX_HEADER_SIZE},
    encrypted_file_format::{
        Header, Metadata, SaltSize, SizeUser, DEFAULT_FORMAT_MARKER,
    },
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
    let mut reader = io::BufReader::new(File::open(&args.file)?);
    let header = read_header(&mut reader)?;
    let metadata: Metadata<Aes256GcmSiv, StreamBE32<_>> =
        read_metadata(&mut reader)?;

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
///
/// If error occurs, the state of reader is unspecified.
fn read_header<R: BufRead>(reader: R) -> csv::Result<Header> {
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

    check_header(&header)?;

    Ok(header)
}

/// Read and parse the metadata section of an encrypted file.
fn read_metadata<A, S>(
    reader: &mut impl io::Read,
) -> bincode::Result<Metadata<A, S>>
where
    A: AeadInPlace + KeySizeUser,
    S: StreamPrimitive<A>,
    A::NonceSize: Sub<S::NonceOverhead>,
    aead::stream::NonceSize<A, S>: ArrayLength<u8>,
    A::KeySize: Add<A::TagSize>,
    <A::KeySize as Add<A::TagSize>>::Output: ArrayLength<u8>,
    aead::stream::NonceSize<A, S>: Add<<A::KeySize as Add<A::TagSize>>::Output>,
    A::NonceSize:
        Add<Sum<aead::stream::NonceSize<A, S>, Sum<A::KeySize, A::TagSize>>>,
    SaltSize: Add<
        Sum<
            A::NonceSize,
            Sum<aead::stream::NonceSize<A, S>, Sum<A::KeySize, A::TagSize>>,
        >,
    >,
    U1: Add<
        Sum<
            SaltSize,
            Sum<
                A::NonceSize,
                Sum<aead::stream::NonceSize<A, S>, Sum<A::KeySize, A::TagSize>>,
            >,
        >,
    >,
    Sum<
        U1,
        Sum<
            SaltSize,
            Sum<
                A::NonceSize,
                Sum<aead::stream::NonceSize<A, S>, Sum<A::KeySize, A::TagSize>>,
            >,
        >,
    >: ArrayLength<u8>,
{
    let mut buf =
        GenericArray::<u8, <Metadata<A, S> as SizeUser>::Size>::default();
    reader.read_exact(&mut buf)?;
    bincode::deserialize_from(buf.as_slice())
}

/// Check the validity of the header.
/// Return an error with explanation if the header is invalid.
fn check_header(header: &Header) -> io::Result<()> {
    fn error_fn(
        e: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, e)
    }

    // check format marker
    if header.format_marker != DEFAULT_FORMAT_MARKER.as_bytes() {
        return Err(error_fn("Invalid format marker indicating that the file is not in our format"));
    }

    // check version is not newer than our supported version
    let version = semver::Version::parse(
        str::from_utf8(&header.version).map_err(error_fn)?,
    )
    .map_err(error_fn)?;
    if version > semver::Version::parse(DEFAULT_FORMAT_VERSION).unwrap() {
        return Err(error_fn(
            "Unrecognized file format version, consider updating this program",
        ));
    }

    // check extension is valid UTF-8
    str::from_utf8(&header.extension).map_err(error_fn)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::encrypted_file_format::DEFAULT_FORMAT_MARKER;

    use super::*;

    #[test]
    fn test_read_header() {
        let s = format!("1.00215,{},a\u{6557}d\n", DEFAULT_FORMAT_MARKER);
        let expected_header = Header {
            version: "1.00215".into(),
            format_marker: DEFAULT_FORMAT_MARKER.into(),
            extension: "a\u{6557}d".into(),
        };
        let actual_header = read_header(s.as_bytes()).unwrap();
        assert_eq!(actual_header, expected_header);
    }

    #[test]
    fn test_read_header_with_invalid_format_marker() {
        let s = "1.00215,invalid_marker,a\u{6557}d\n";
        assert!(read_header(s.as_bytes()).is_err());
    }

    #[test]
    fn test_read_metadata() {
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let expected_md: Metadata<Aes256GcmSiv, StreamBE32<_>> = Metadata {
            compression_enabled: rng.gen(),
            salt: rng.gen(),
            nonce_dek: rng.gen::<[u8; 12]>().into(),
            nonce_body: rng.gen::<[u8; 7]>().into(),
            encrypted_dek: std::array::from_fn(|_| rng.gen()).into(),
        };
        let s = bincode::serialize(&expected_md).unwrap();
        let actual_md: Metadata<Aes256GcmSiv, StreamBE32<_>> =
            read_metadata(&mut s.as_slice()).unwrap();
        assert_eq!(actual_md, expected_md);
    }
}
