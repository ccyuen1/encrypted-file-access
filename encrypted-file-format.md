# Encrypted File Format Specification

Version: 0.1

This file specifies the format of the encrypted file used in this program.

An encrypted file consists of three parts: a header, a metadata section, and a body.

## Header

The header is in raw UTF-8 text with a fixed number of lines separated by line feeds (0x0A).
Leading and trailing spaces should not exist.

First line: Format version number in text. Example: 0.1

Second line: It is always "encrypted-file-format" (without the quotes) to mark that the file is in our format.

The final line feed ends the header.

## Metadata Section

Currently, the metadata section has a fixed size.

The first byte is 0x01 if the plaintext is compressed before encryption, otherwise 0x00.
If the plaintext is compressed, it is compressed in LZMA2 format.

The salt

The initialization vector (IV) for Argon2id

The **TODO** bytes are the 256-bit data encryption key encrypted using AES-GCM-SIV with the salt and IV.

## Body
