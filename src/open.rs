use core::str;
use std::{
    ffi::OsStr,
    fs::{File, OpenOptions},
    io::{self, BufRead, Write},
    ops::{Add, Sub},
    path::{Path, PathBuf},
    process::Child,
};

use aead::{
    consts::U1,
    stream::{DecryptorBE32, StreamBE32, StreamPrimitive},
    Aead, AeadInPlace, Key, KeyInit, KeySizeUser,
};
use aes_gcm_siv::Aes256GcmSiv;
use anyhow::{anyhow, Context};
use clap::Args;
use generic_array::{typenum::Sum, ArrayLength, GenericArray};
use secrecy::{ExposeSecret, Secret};
use tempfile::tempdir;
use uuid::Uuid;

use crate::{
    config::{csv_reader_builder, MAX_HEADER_SIZE},
    encrypted_file_format::{
        Header, Metadata, SaltSize, SizeUser, DEFAULT_FORMAT_MARKER,
        DEFAULT_FORMAT_VERSION,
    },
    encryption::{prompt_for_password_and_derive_kek, stream_decrypt},
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
    let mut in_reader = io::BufReader::new(File::open(&args.file)?);
    let header = read_header(&mut in_reader)?;
    let metadata: Metadata<Aes256GcmSiv, StreamBE32<_>> =
        read_metadata(&mut in_reader)?;

    // prepare a temporary file for decryption
    let temp_dir = tempdir()?;
    let decrypted_file_uuid = Uuid::new_v4();
    let decrypted_file_path = temp_dir.path().join(
        decrypted_file_uuid.to_string()
            + "."
            + str::from_utf8(&header.extension).unwrap(),
    );
    let decrypted_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&decrypted_file_path)?;
    let mut decrypted_writer = io::BufWriter::new(decrypted_file);

    // decrypt the DEK
    let kek = Secret::new(prompt_for_password_and_derive_kek(&metadata.salt)?);
    let cipher = Aes256GcmSiv::new(kek.expose_secret());
    let dek_secret = Secret::new(
        cipher
            .decrypt(&metadata.nonce_dek, metadata.encrypted_dek.as_slice())?,
    );
    if dek_secret.expose_secret().len() != Aes256GcmSiv::key_size() {
        panic!("Unexpected length {} of decrypted DEK, expected {}. This is a bug in this program.",
            dek_secret.expose_secret().len(), Aes256GcmSiv::key_size());
    }
    let dek = Key::<Aes256GcmSiv>::from_slice(dek_secret.expose_secret());

    // decrypt the body
    let decryptor: DecryptorBE32<Aes256GcmSiv> =
        DecryptorBE32::new(dek, &metadata.nonce_body);
    stream_decrypt(decryptor, &mut in_reader, &mut decrypted_writer)?;

    // flush the decrypted file
    decrypted_writer.flush()?;
    drop(decrypted_writer);
    drop(in_reader);

    // open the decrypted file with the specified application and wait for it to finish
    open_file_with(
        &decrypted_file_path,
        args.executable.as_deref(),
        temp_dir.path(),
    )?
    .wait()
    .with_context(|| "Waiting for application to finish")?;

    // TODO: create a new password-protected file alongside the original file
    //       reflecting the modifications made to the temporary file

    // TODO: clean up the temporary file safely with best effort

    // TODO: replace the original file with the new file
    temp_dir.close()?;

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

    // check format marker
    if header.format_marker != DEFAULT_FORMAT_MARKER.as_bytes() {
        return Err(error_fn("Invalid format marker indicating that the file is not in our format"));
    }

    // check extension is valid UTF-8
    str::from_utf8(&header.extension).map_err(error_fn)?;

    Ok(())
}

/// Open a file with the specified application or the default application.
/// Return the [`Child`] if successful.
fn open_file_with(
    path: impl AsRef<OsStr>,
    app: Option<&Path>,
    current_dir: impl AsRef<Path>,
) -> anyhow::Result<Child> {
    let mut command = if let Some(exe) = app {
        open::with_command(path, exe.to_string_lossy())
    } else {
        open::commands(path).into_iter().next().ok_or(anyhow!(
            "Cannot find an application to open the decrypted file"
        ))?
    };
    let child = command.current_dir(current_dir).spawn()?;
    Ok(child)
}

#[cfg(test)]
mod tests {
    use crate::encrypted_file_format::DEFAULT_FORMAT_MARKER;

    use super::*;

    #[test]
    fn test_read_header_with_valid_header() {
        let s = format!("0.0.205,{},a\u{6557}d\n", DEFAULT_FORMAT_MARKER);
        let expected_header = Header {
            version: "0.0.205".into(),
            format_marker: DEFAULT_FORMAT_MARKER.into(),
            extension: "a\u{6557}d".into(),
        };
        let actual_header = read_header(s.as_bytes()).unwrap();
        assert_eq!(actual_header, expected_header);
    }

    #[test]
    fn test_read_header_with_invalid_format_marker() {
        let s = "0.1.0,invalid_marker,a\u{6557}d\n";
        assert!(read_header(s.as_bytes()).is_err());
    }

    #[test]
    fn test_read_header_with_invalid_utf8() {
        let mut s = Vec::new();
        s.extend(b"\x45\x22\xAA,");
        s.extend(DEFAULT_FORMAT_MARKER.as_bytes());
        s.extend(b",txt\n");
        assert!(read_header(s.as_slice()).is_err());

        s.clear();
        s.extend(b"0.1.0,\x00\xAB\xAB,txt\n");
        assert!(read_header(s.as_slice()).is_err());

        s.clear();
        s.extend(b"0.1.0,");
        s.extend(DEFAULT_FORMAT_MARKER.as_bytes());
        s.extend(b",\xEE\xEF\n");
        assert!(read_header(s.as_slice()).is_err());
    }

    #[test]
    fn test_read_header_with_invalid_version() {
        let mut s = Vec::new();
        s.extend(u64::MAX.to_string().as_bytes());
        s.extend(b".0.0,");
        s.extend(DEFAULT_FORMAT_MARKER.as_bytes());
        s.extend(b",txt\n");
        assert!(read_header(s.as_slice()).is_err());
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
