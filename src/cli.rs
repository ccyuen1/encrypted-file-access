use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(version, author)]
/// A simple program to create, view, and modify an encrypted file in a specific format
pub struct Cli {
    #[command(subcommand)]
    pub action: Actions,
}

#[derive(Subcommand, Debug)]
pub enum Actions {
    /// Create a encrypted file
    Create(CreateArgs),

    /// Open an encrypted file
    Open(OpenArgs),

    /// Alias of create
    C(CreateArgs),

    /// Alias of open
    O(OpenArgs),
}

#[derive(Args, Debug)]
pub struct CreateArgs {
    /// Path to the encrypted file to create
    pub file: PathBuf,
}

#[derive(Args, Debug)]
pub struct OpenArgs {
    /// Path to the encrypted file to open
    pub file: PathBuf,

    #[arg(short, long)]
    /// Executable to open the decrypted file. If not given, use the default system handler
    pub executable: Option<PathBuf>,
}
