use std::path::PathBuf;

use anyhow::{bail, Result};
use bytesize::ByteSize;

use pesigitg_common::{DEFAULT_INTF, DEFAULT_QUEUES, MAX_CONFIG_SIZE, MAX_QUEUES};

pub struct FileConfig {
    pub ports: Vec<u16>,
    pub interface: String,
    pub queues: u32,
}

pub fn parse_config(path: &PathBuf) -> Result<FileConfig> {
    let size = std::fs::metadata(path)?.len();

    if size > MAX_CONFIG_SIZE {
        let byte_size = ByteSize::b(size);

        bail!("config file exceeds {} limit ({} bytes)", size, byte_size);
    }

    let content = std::fs::read_to_string(path)?;
    let mut ports = Vec::new();
    let mut interface = DEFAULT_INTF.to_string();
    let mut queues: u32 = DEFAULT_QUEUES;

    for line in content.lines() {
        let line = line.trim();

        if line.is_empty() || line.starts_with('#') { continue; }

        if let Some((k, v)) = line.split_once('=') {
            match k.trim() {
                "port" => ports.push(v.trim().parse::<u16>()?),
                "interface" => interface = v.trim().to_string(),
                "queues" => {
                    let q = v.trim().parse::<u32>()?;
                    if q == 0 || q > MAX_QUEUES {
                        bail!("queues must be between 1 and {}", MAX_QUEUES);
                    }
                    queues = q;
                }
                _ => {}
            }
        }
    }

    Ok(FileConfig { ports, interface, queues })
}
