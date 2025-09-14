use anyhow::Result;

mod model;
mod utils;
mod chunk;
mod crypto;
mod storage;
mod watcher;
mod search;
mod gui;
mod config;
mod monitoring;
mod access_control;
mod logging;
mod security;

fn main() -> Result<(), eframe::Error> {
    env_logger::init();
    gui::run_app()
}
