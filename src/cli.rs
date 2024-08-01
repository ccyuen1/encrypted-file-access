use clap::{Parser, Subcommand};

use crate::{create::CreateArgs, open::OpenArgs};

#[derive(Parser, Debug)]
#[command(version, author)]
/// A simple program to create, view, and modify an encrypted file in a specific format
pub struct Cli {
    #[command(subcommand)]
    pub action: Actions,
}

#[derive(Subcommand, Debug)]
pub enum Actions {
    /// Create an encrypted file
    Create(CreateArgs),

    /// Open an encrypted file
    Open(OpenArgs),

    /// Alias of create
    C(CreateArgs),

    /// Alias of open
    O(OpenArgs),
}
