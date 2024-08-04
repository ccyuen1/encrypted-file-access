use core::str;
use std::{
    ffi::{OsStr, OsString},
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
use anyhow::{anyhow, bail, Context};
use clap::Args;
use either::Either::{Left, Right};
use generic_array::{typenum::Sum, ArrayLength, GenericArray};
use secrecy::{ExposeSecret, Secret};
use tempfile::{tempdir, TempDir};
use uuid::Uuid;
use xz2::write::XzDecoder;

use crate::{
    config::{csv_reader_builder, MAX_HEADER_SIZE},
    create::{self, CreateArgs},
    encrypted_file_format::{Header, Metadata, SaltSize, SizeUser},
    encryption::{derive_kek, prompt_for_password, stream_decrypt},
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
/// If the password is not provided, the user will be prompted to enter it.
///
/// # Panics
/// Panics if `getrandom` is unable to provide secure entropy to re-encrypt the file.
///
/// # Examples
/// ```no_run
/// use std::path::PathBuf;
/// use encrypted_file_access::open::{OpenArgs, open};
/// let args = OpenArgs {
///     file: PathBuf::from("example.encrypted"),
///     executable: Some(PathBuf::from("notepad.exe")),
/// };
/// open(&args, None).unwrap();
/// // User will be prompted to enter a password
/// ```
pub fn open(
    args: &OpenArgs,
    password: Option<Secret<String>>,
) -> anyhow::Result<()> {
    // obtain the password
    let password = match password {
        Some(pw) => pw,
        None => prompt_for_password(false)?,
    };

    let mut in_reader = io::BufReader::new(File::open(&args.file)?);
    let header = read_header(&mut in_reader)?;
    let metadata: Metadata<Aes256GcmSiv, StreamBE32<_>> =
        read_metadata(&mut in_reader)?;
    let (temp_dir, decrypted_file_path) =
        decrypt_to_temp_file(in_reader, &header, &metadata, &password)?;

    // open the decrypted file with the specified application and wait for it to finish
    open_file_with(
        &decrypted_file_path,
        args.executable.as_deref(),
        temp_dir.path(),
    )?
    .wait()
    .with_context(|| "Waiting for application to finish")?;

    // create a new password-protected file alongside the original file
    let new_file_path = create_encrypted_file_alongside_path(
        &args.file,
        decrypted_file_path.clone(),
        !metadata.compression_enabled,
        header.xz_level,
        Some(password),
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

/// Decrypt password-protected data from reader to a newly-created temporary file.
/// Return the temporary directory containing the file and the path to the file.
pub fn decrypt_to_temp_file(
    mut reader: impl BufRead,
    header: &Header,
    metadata: &Metadata<Aes256GcmSiv, StreamBE32<Aes256GcmSiv>>,
    password: &Secret<String>,
) -> anyhow::Result<(TempDir, PathBuf)> {
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
    let decrypted_writer = io::BufWriter::new(decrypted_file);

    // derive the KEK
    let kek = derive_kek(password, &metadata.salt)?;

    // decrypt the DEK
    let cipher = Aes256GcmSiv::new(kek.expose_secret());
    drop(kek); // done with KEK
    let dek = Secret::new(
        cipher
            .decrypt(&metadata.nonce_dek, metadata.encrypted_dek.as_slice())?,
    );
    if dek.expose_secret().len() != Aes256GcmSiv::key_size() {
        panic!("Unexpected length {} of decrypted DEK, expected {}. This is a bug in this program.",
            dek.expose_secret().len(), Aes256GcmSiv::key_size());
    }

    // instantiate the decompressor if compression is enabled
    let mut writer = if metadata.compression_enabled {
        Left(XzDecoder::new(decrypted_writer))
    } else {
        Right(decrypted_writer)
    };

    // decrypt the body
    let decryptor: DecryptorBE32<Aes256GcmSiv> = DecryptorBE32::new(
        Key::<Aes256GcmSiv>::from_slice(dek.expose_secret()),
        &metadata.nonce_body,
    );
    drop(dek); // done with DEK
    stream_decrypt(decryptor, &mut reader, &mut writer)?;

    // flush the decrypted file
    writer.flush()?;
    drop(writer);
    drop(reader);

    Ok((temp_dir, decrypted_file_path))
}

/// Read and parse the header of an encrypted file.
/// This will error if the header is invalid.
///
/// If error occurs, the state of reader is unspecified.
pub(crate) fn read_header<R: BufRead>(reader: R) -> csv::Result<Header> {
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
pub(crate) fn read_metadata<A, S>(
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
    if version > semver::Version::parse(Header::DEFAULT_VERSION).unwrap() {
        return Err(error_fn(
            "Unrecognized file format version, consider updating this program",
        ));
    }

    // check format marker
    if header.format_marker != Header::DEFAULT_FORMAT_MARKER.as_bytes() {
        return Err(error_fn("Invalid format marker indicating that the file is not in our format"));
    }

    // check extension is valid UTF-8
    str::from_utf8(&header.extension).map_err(error_fn)?;

    // check XZ level is valid
    if !(Header::MIN_XZ_LEVEL..=Header::MAX_XZ_LEVEL).contains(&header.xz_level)
    {
        return Err(error_fn(format!(
            "Invalid XZ compression level: {}",
            header.xz_level
        )));
    }

    Ok(())
}

/// Open a file or URL with the specified application or the default application.
/// Return the [`Child`] if successful.
fn open_file_with(
    path: impl AsRef<OsStr>,
    app: Option<&Path>,
    current_dir: impl AsRef<Path>,
) -> anyhow::Result<Child> {
    let mut command = if let Some(exe) = app {
        open_wait::with_command(path, exe)
    } else {
        open_wait::commands(path).into_iter().next().ok_or(anyhow!(
            "Cannot find an application to open the decrypted file"
        ))?
    };
    let child = command.current_dir(current_dir).spawn()?;
    Ok(child)
}

/// Create a new password-protected file as a sibling of a file path.
/// Return the path of the new file.
///
/// If the password is not provided,
/// the user will be prompted to enter a password.
pub(crate) fn create_encrypted_file_alongside_path(
    sibling_path: &Path,
    decrypted_file_path: PathBuf,
    no_compress: bool,
    xz_level: u32,
    password: Option<Secret<String>>,
) -> anyhow::Result<PathBuf> {
    fn lacks_component_error() -> anyhow::Error {
        anyhow!("Argument `file` lacks a component in the path")
    }
    let mut temp_out_file_name = OsString::from(Uuid::new_v4().to_string());
    temp_out_file_name.push("-");
    temp_out_file_name
        .push(sibling_path.file_name().ok_or_else(lacks_component_error)?);
    let temp_out_file_path = sibling_path
        .parent()
        .ok_or_else(lacks_component_error)?
        .join(&temp_out_file_name);
    let create_args = CreateArgs {
        out_file: temp_out_file_path.clone(),
        src: Some(decrypted_file_path),
        extension: None,
        no_compress,
        xz_level,
    };
    create::create(&create_args, password)
        .with_context(|| "Re-encrypting the file")?;
    Ok(temp_out_file_path)
}

/// Replace the content of a file with zeros.
pub(crate) fn fill_file_with_zeros(path: &Path) -> anyhow::Result<()> {
    let mut f = OpenOptions::new().write(true).open(path)?;
    let mut remaining_len = f.metadata()?.len();
    const BUF_SIZE: usize = 4 * 1024;
    let zeros = vec![0u8; BUF_SIZE];
    while remaining_len > 0 {
        let bytes_written =
            f.write(&zeros[..remaining_len.min(BUF_SIZE as u64) as usize])?;
        if bytes_written == 0 {
            bail!("The file was not fully written");
        }
        remaining_len -= bytes_written as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::encrypted_file_format::Header;

    use super::*;

    #[test]
    fn test_read_header_with_valid_header() {
        let s =
            format!("0.0.205,{},a\u{6557}d,9\n", Header::DEFAULT_FORMAT_MARKER);
        let expected_header = Header {
            version: "0.0.205".into(),
            format_marker: Header::DEFAULT_FORMAT_MARKER.into(),
            extension: "a\u{6557}d".into(),
            xz_level: 9,
        };
        let actual_header = read_header(s.as_bytes()).unwrap();
        assert_eq!(actual_header, expected_header);
    }

    #[test]
    fn test_read_header_with_invalid_format_marker() {
        let s = "0.1.0,invalid_marker,a\u{6557}d,6\n";
        assert!(read_header(s.as_bytes()).is_err());
    }

    #[test]
    fn test_read_header_with_invalid_utf8() {
        let mut s = Vec::new();
        s.extend(b"\x45\x22\xAA,");
        s.extend(Header::DEFAULT_FORMAT_MARKER.as_bytes());
        s.extend(b",txt,6\n");
        assert!(read_header(s.as_slice()).is_err());

        s.clear();
        s.extend(b"0.1.0,\x00\xAB\xAB,txt,6\n");
        assert!(read_header(s.as_slice()).is_err());

        s.clear();
        s.extend(b"0.1.0,");
        s.extend(Header::DEFAULT_FORMAT_MARKER.as_bytes());
        s.extend(b",\xEE\xEF,6\n");
        assert!(read_header(s.as_slice()).is_err());

        s.clear();
        s.extend(b"0.1.0,");
        s.extend(Header::DEFAULT_FORMAT_MARKER.as_bytes());
        s.extend(b",txt,\x00\xAB\xAB\n");
        assert!(read_header(s.as_slice()).is_err());
    }

    #[test]
    fn test_read_header_with_invalid_version() {
        let mut s = Vec::new();
        s.extend(u64::MAX.to_string().as_bytes());
        s.extend(b".0.0,");
        s.extend(Header::DEFAULT_FORMAT_MARKER.as_bytes());
        s.extend(b",txt,6\n");
        assert!(read_header(s.as_slice()).is_err());
    }
    #[test]
    fn test_read_header_with_invalid_xz_level() {
        let mut s = Vec::new();
        s.extend(b"0.1.0,");
        s.extend(Header::DEFAULT_FORMAT_MARKER.as_bytes());
        s.extend(b",txt,");

        let mut s1 = s.clone();
        s1.extend(b"-1\n");
        assert!(read_header(s1.as_slice()).is_err());

        let mut s2 = s.clone();
        s2.extend(b"10\n");
        assert!(read_header(s2.as_slice()).is_err());

        let mut s3 = s.clone();
        s3.extend(b"0\n");
        assert!(read_header(s3.as_slice()).is_ok());

        let mut s4 = s.clone();
        s4.extend(b"9\n");
        assert!(read_header(s4.as_slice()).is_ok());
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

    #[test]
    fn test_open_file_with_default_app() -> anyhow::Result<()> {
        let dir = tempdir()?;
        let file_path = dir.path().join("test_file.txt");
        let file = File::create_new(&file_path)?;
        drop(file);
        open_file_with(&file_path, None, &dir)?.kill()?;
        dir.close()?;
        Ok(())
    }
}
