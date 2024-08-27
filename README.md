# Encrypted File Access

This software helps users create, view, and modify a password-protected file in a format defined by this software. Suitable for archiving a file that requires frequent modifications.

*Disclaimer: This software is only suitable for files with a low security requirement because the decrypted file is stored insecurely in the operating system's temp directory for convenient temporary access. Use it on your own risk.*

## Features

- Create a password-protected file from a source file using AES-GCM-SIV encryption with a 256-bit key.
- Open a password-protected file that is in our format: use a user-specified executable to view and/or modify the decrypted file. Modifications will be made to the encrypted file after the user-specified executable's process terminates.
- Change the password of a password-protected file that is in our format.

## Build

```sh
git clone https://github.com/ccyuen1/encrypted-file-access.git
cd encrypted-file-access
cargo build --release
```

The binary executable will be compiled to the ./target/release directory.

## Usage

```text
$ encrypted-file-access --help
A simple program to create, view, and modify an encrypted file in a specific format

Usage: encrypted-file-access.exe <COMMAND>

Commands:
  create           Create a password-protected file
  open             Open a password-protected file
  change-password  Change the password of a password-protected file
  c                Alias of create
  o                Alias of open
  cp               Alias of change-password
  help             Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

```text
$ encrypted-file-access create --help
Create a password-protected file

Usage: encrypted-file-access.exe create [OPTIONS] <OUT_FILE>

Arguments:
  <OUT_FILE>  Path to the encrypted file to create

Options:
  -s, --src <SRC>              Path to the plaintext file to be encrypted. If missing, an empty file is created
  -e, --extension <EXTENSION>  Extension for the decrypted file. Overwritten by extension of src if provided. Default: txt
      --no-compress            If given, the plaintext file is not compressed before encryption
      --xz-level <XZ_LEVEL>    Compression level of XZ algorithm. Valid values are 0-9. Ignored when --no-compress is given [default: 6]
  -h, --help                   Print help
```

```text
$ encrypted-file-access open --help
Open a password-protected file

Usage: encrypted-file-access.exe open [OPTIONS] <FILE>

Arguments:
  <FILE>  Path to the encrypted file to open

Options:
  -e, --executable <EXECUTABLE>  Executable to open the decrypted file. If not given, use the default system handler
  -h, --help                     Print help
```

```text
$ encrypted-file-access change-password --help
Change the password of a password-protected file

Usage: encrypted-file-access.exe change-password <FILE> [NO_COMPRESS] [XZ_LEVEL]

Arguments:
  <FILE>         Path to the encrypted file
  [NO_COMPRESS]  Disable or enable compression if provided [possible values: true, false]
  [XZ_LEVEL]     New XZ compression level (0-9), ignored if compression is disabled

Options:
  -h, --help  Print help
```

## Documentation

The password-protected file format is specified in [encrypted-file-format.md](encrypted-file-format.md).

## To-dos

- Allow users to decrypt a password-protected file and save to file system.

## Acknowledgement

This software depends on many libraries on [crates.io](https://crates.io). Give thanks to the library authors!
