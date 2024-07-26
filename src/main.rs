use clap::Parser;

use cli::{Actions, Cli};

mod cli;
mod create;
mod open;

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
