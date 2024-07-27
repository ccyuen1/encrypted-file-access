# Encrypted File Format Specification

**Version: 0.1**

This file specifies the format of the encrypted file used in this program.

An encrypted file consists of three parts: a header, a metadata section, and a body.

## Header

The header is in raw UTF-8 text with a fixed number of lines.
Each line is ended by exactly one line feed (0x0A).
The size of the header is subject to change.
Leading and trailing spaces should not exist.

The lines are in the following order.

Line 1: Format version number in text. Example: 0.1

Line 2: It is always "encrypted-file-format" (without quotes) to mark that the file is in our format.

An extra line feed ends the header.

## Metadata Section

The metadata section has a fixed size. It stores the metadata in the following order.

1. The first byte is 0x01 if the plaintext file is compressed before encryption, otherwise 0x00.
   If the plaintext is compressed, it is compressed in LZMA2 format.

2. The salt for key derivation function, i.e., Argon2id, in 32 bytes in plain binary format.

3. The nonce, aka initialization vector (IV), for encryption algorithm, i.e., AES-GCM-SIV, in 12 bytes. This is used to encrypt the DEK.

4. The nonce for AES-GCM-SIV in 12 bytes for the encryption of the body.

5. The 48-byte ciphertext of the 256-bit data encryption key (DEK).
   It is encrypted by AES-GCM-SIV using the key encryption key (KEK) and the nonce for DEK.
   The KEK is derived from the salt and a user-provided password using Argon2id.

## Body

The ciphertext of the file content, after AES-GCM-SIV encryption with the DEK and the nonce for body.
