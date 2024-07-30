use clap::Parser;

use encrypted_file_access::{
    cli::{Actions, Cli},
    create, open,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let cli = Cli::parse();
    log::debug!("{:?}", cli);

    match &cli.action {
        Actions::Create(c) | Actions::C(c) => create::create(c)?,
        Actions::Open(o) | Actions::O(o) => open::open(o)?,
    }

    Ok(())
}
