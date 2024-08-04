use anyhow::bail;
use clap::Parser;

use encrypted_file_access::{
    change_password,
    cli::{Actions, Cli},
    create, open,
};

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match &cli.action {
        Actions::Create(c) | Actions::C(c) => create::create(c, None)?,
        Actions::Open(o) | Actions::O(o) => open::open(o, None)?,
        Actions::ChangePassword(args) | Actions::CP(args) => {
            change_password::change_password(args, None, None)?
        }
        _ => bail!("Unknown action: {:?}", cli.action),
    }

    Ok(())
}
