# Encrypted File Format Specification

**Version: 0.1**

This file specifies the format of the encrypted file used in this program.

An encrypted file consists of three parts: a header, a metadata section, and a body.

## Header

The header is in UTF-8 CSV format with one line.
Each field is ended by exactly one comma.
Leading and trailing spaces should not exist for any field.
A line feed ends the header.

The fields are in the following order.

Field 1: Format version number in text. Example: 0.1

Field 2: It is always "encrypted-file-format" (without quotes) to mark that the file is in our format.

Field 3: Extension of the decrypted file. Example: txt

## Metadata Section

The metadata section has a fixed size. It stores the metadata in the following order.

1. The first byte is 0x01 if the plaintext file is compressed before encryption, otherwise 0x00.
   If the plaintext is compressed, it is compressed in XZ format.

2. The salt for key derivation function, i.e., Argon2id, in 32 bytes in plain binary format.

3. The nonce, aka initialization vector (IV), in 12 bytes for the encryption algorithm. This is used to encrypt the DEK.

4. The nonce in 12 bytes for the encryption of the body.

5. The 48-byte ciphertext of the 256-bit data encryption key (DEK).
   It is encrypted by AES-GCM-SIV using the key encryption key (KEK) and the nonce for DEK.
   The KEK is derived from the salt and a user-provided password using Argon2id.

## Body

The ciphertext of the file content. The plaintext is encrypted by streaming encryption with [aead::stream::EncryptorBE32](https://docs.rs/aead/0.5.2/aead/stream/type.EncryptorBE32.html) with the DEK, the nonce for body, and AES-GCM-SIV.
