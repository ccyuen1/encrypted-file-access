use std::path::PathBuf;

use clap::Args;
use open::commands;

#[derive(Args, Debug)]
/// Arguments for opening an existing encrypted file
pub struct OpenArgs {
    /// Path to the encrypted file to open
    pub file: PathBuf,

    #[arg(short, long)]
    /// Executable to open the decrypted file. If not given, use the default system handler
    pub executable: Option<PathBuf>,
}

pub fn open(args: &OpenArgs) -> Result<(), Box<dyn std::error::Error>> {
    todo!()
}
