# Encrypted File Access

**This software is under development and incomplete.**

This software helps users create, view, and modify a password-protected file in a format defined by this software. Suitable for archiving a file that requires frequent modifications.

*Disclaimer: This software is only suitable for files with a low security requirement because the decrypted file is stored insecurely in the operating system's temp directory for convenient temporary access. Use it on your own risk.*

## Features

- Create a password-protected file from a source file using AES-GCM-SIV encryption with a 256-bit key.
- Open a password-protected file that is in our format: use a user-specified executable to view and/or modify the decrypted file. Modifications will be made to the encrypted file after the user-specified executable's process terminates.
- Change the password of a password-protected file that is in our format.

## Documentation

The password-protected file format is specified in [encrypted-file-format.md](encrypted-file-format.md).

## TODO List

- Allow users change the password. This should change the data encryption key (DEK).
