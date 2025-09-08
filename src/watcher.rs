use notify::{recommended_watcher, RecursiveMode, Result as NotifyResult, Event, Watcher};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver};

pub fn watch_folder(path: PathBuf) -> NotifyResult<Receiver<Event>> {
    let (tx, rx) = channel();
    let mut watcher = recommended_watcher(move |res| {
        if let Ok(event) = res {
            let _ = tx.send(event);
        }
    })?;

    watcher.watch(&path, RecursiveMode::Recursive)?;
    Ok(rx)
}
