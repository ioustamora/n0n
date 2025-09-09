use anyhow::Result;

mod model;
mod utils;
mod chunk;
mod crypto;
mod storage;
mod watcher;
mod search;
mod gui;

fn main() -> Result<(), eframe::Error> {
    env_logger::init();
    gui::run_app()
}
