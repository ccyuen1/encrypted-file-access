use clap::{Parser, Subcommand};

use crate::{
    change_password::ChangePasswordArgs, create::CreateArgs, open::OpenArgs,
};

#[derive(Parser, Debug)]
#[command(version, author)]
/// A simple program to create, view, and modify an encrypted file in a specific format
pub struct Cli {
    #[command(subcommand)]
    pub action: Actions,
}

#[non_exhaustive]
#[derive(Subcommand, Debug)]
pub enum Actions {
    /// Create a password-protected file
    Create(CreateArgs),

    /// Open a password-protected file
    Open(OpenArgs),

    /// Change the password of a password-protected file
    ChangePassword(ChangePasswordArgs),

    /// Alias of create
    C(CreateArgs),

    /// Alias of open
    O(OpenArgs),

    /// Alias of change-password
    CP(ChangePasswordArgs),
}
