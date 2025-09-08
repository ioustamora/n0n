use anyhow::Result;

mod model;
mod utils;
mod chunk;
mod crypto;
mod storage;
mod watcher;
mod search;
mod gui;

fn main() -> Result<()> {
    env_logger::init();
    gui::run_gui()?;
    Ok(())
}
