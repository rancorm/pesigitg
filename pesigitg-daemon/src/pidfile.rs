use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process;

use anyhow::{bail, Result};
use nix::fcntl::{Flock, FlockArg};

pub struct PidFile {
    path: PathBuf,
    _lock: Flock<File>,
}

impl PidFile {
    pub fn create(path: &Path) -> Result<Self> {
        let mut file = File::options()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .open(path)?;

        let lock = match Flock::lock(file.try_clone()?, FlockArg::LockExclusiveNonblock) {
            Ok(lock) => lock,
            Err(_) => bail!("another instance is already running (PID file locked)"),
        };

        write!(file, "{}", process::id())?;

        Ok(PidFile {
            path: path.to_path_buf(),
            _lock: lock,
        })
    }
}

impl Drop for PidFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
