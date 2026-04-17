// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

use std::fmt;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use nix::fcntl::{Flock, FlockArg};

use pesigitg_common::current_pid;

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

        write!(file, "{}", current_pid())?;

        Ok(PidFile {
            path: path.to_path_buf(),
            _lock: lock,
        })
    }
}

impl fmt::Display for PidFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.path.display())
    }
}

impl Drop for PidFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
