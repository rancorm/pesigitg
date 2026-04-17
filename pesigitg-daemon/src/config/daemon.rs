// SPDX-License-Identifier: GPL-3.0-or-later OR Commercial
// Copyright (c) 2026 Jonathan Cormier
// This file is part of Pesigitg.

use core::fmt;
use std::path::PathBuf;

use anyhow::{bail, Result};
use bytesize::ByteSize;

use pesigitg_common::{DEFAULT_INTF, DEFAULT_QUEUES, MAX_CONFIG_SIZE, MAX_QUEUES};

#[derive(Debug, Clone)]
pub struct FileConfig {
    pub ports: Vec<u16>,
    pub interface: String,
    pub queues: u32,
    pub route_config: Option<PathBuf>,
    pub status_socket: Option<PathBuf>,
}

impl FileConfig {
    pub fn from_file(path: &PathBuf) -> Result<FileConfig> {
        let size = std::fs::metadata(path)?.len();

        if size > MAX_CONFIG_SIZE {
            let byte_size = ByteSize::b(size);

            bail!("config file exceeds {} limit ({} bytes)", size, byte_size);
        }

        let content = std::fs::read_to_string(path)?;
        let mut ports = Vec::new();
        let mut interface = DEFAULT_INTF.to_string();
        let mut queues: u32 = DEFAULT_QUEUES;
        let mut route_config: Option<PathBuf> = None;
        let mut status_socket: Option<PathBuf> = None;

        for line in content.lines() {
            let line = line.trim();

            // Skip empty or comment lines
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
                    "route_config" => {
                        let p = PathBuf::from(v.trim());
                        route_config = Some(if p.is_relative() {
                            path.parent().unwrap_or(path).join(&p)
                        } else {
                            p
                        });
                    }
                    "status_socket" => {
                        let s = v.trim();
                        if !s.is_empty() {
                            status_socket = Some(PathBuf::from(s));
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(FileConfig { ports, interface, queues, route_config, status_socket })
    }
}

impl fmt::Display for FileConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "daemon config:")?;
        writeln!(f, "  interface: {}", self.interface)?;
        writeln!(f, "  queues: {}", self.queues)?;
        write!(f, "  ports:")?;

        for port in self.ports.iter() {
            write!(f, " {}", port)?;
        }

        writeln!(f)?;
        writeln!(f, "  route config: {}",
            self.route_config
            .as_deref()
            .and_then(|p| p.to_str())
            .unwrap_or("<none>"))?;
        writeln!(f, "  status socket: {}",
            self.status_socket
            .as_deref()
            .and_then(|p| p.to_str())
            .unwrap_or("<disabled>"))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_with_typical_values() {
        let config = FileConfig {
            ports: vec![443, 8443],
            interface: "eth0".to_string(),
            queues: 4,
            route_config: None,
            status_socket: None,
        };

        assert_eq!(config.ports, vec![443, 8443]);
        assert_eq!(config.interface, "eth0");
        assert_eq!(config.queues, 4);
    }

    #[test]
    fn single_port() {
        let config = FileConfig {
            ports: vec![443],
            interface: "enp1s0f0".to_string(),
            queues: 1,
            route_config: None,
            status_socket: None,
        };
        
        assert_eq!(config.ports.len(), 1);
        assert_eq!(config.ports[0], 443);
    }

    #[test]
    fn empty_ports() {
        let config = FileConfig {
            ports: vec![],
            interface: "lo".to_string(),
            queues: 0,
            route_config: None,
            status_socket: None,
        };
        
        assert!(config.ports.is_empty());
    }

    #[test]
    fn many_ports() {
        let ports: Vec<u16> = (1000..=1100).collect();
        let config = FileConfig {
            ports: ports.clone(),
            interface: "eth0".to_string(),
            queues: 8,
            route_config: None,
            status_socket: None,
        };
        
        assert_eq!(config.ports.len(), 101);
        assert_eq!(config.ports, ports);
    }

    #[test]
    fn port_boundary_values() {
        let config = FileConfig {
            ports: vec![0, 1, 80, 443, 65535],
            interface: "eth0".to_string(),
            queues: 1,
            route_config: None,
            status_socket: None,
        };
        
        assert_eq!(*config.ports.first().unwrap(), 0);
        assert_eq!(*config.ports.last().unwrap(), 65535);
    }

    #[test]
    fn interface_names() {
        for name in ["eth0", "enp1s0f0", "ens3", "lo", "veth0@if2"] {
            let config = FileConfig {
                ports: vec![443],
                interface: name.to_string(),
                queues: 1,
                route_config: None,
                status_socket: None,
            };
            
            assert_eq!(config.interface, name);
        }
    }

    #[test]
    fn high_queue_count() {
        let config = FileConfig {
            ports: vec![443],
            interface: "eth0".to_string(),
            queues: 128,
            route_config: None,
            status_socket: None,
        };
        
        assert_eq!(config.queues, 128);
    }

    #[test]
    fn clone_produces_independent_copy() {
        let config = FileConfig {
            ports: vec![443, 8443],
            interface: "eth0".to_string(),
            queues: 4,
            route_config: None,
            status_socket: None,
        };
        
        let mut cloned = config.clone();
        
        cloned.ports.push(9443);
        cloned.interface = "eth1".to_string();
        cloned.queues = 8;

        // Original is unaffected
        assert_eq!(config.ports, vec![443, 8443]);
        assert_eq!(config.interface, "eth0");
        assert_eq!(config.queues, 4);

        // Clone has new values
        assert_eq!(cloned.ports, vec![443, 8443, 9443]);
        assert_eq!(cloned.interface, "eth1");
        assert_eq!(cloned.queues, 8);
    }

    #[test]
    fn debug_format_contains_fields() {
        let config = FileConfig {
            ports: vec![443],
            interface: "eth0".to_string(),
            queues: 4,
            route_config: None,
            status_socket: None,
        };
        
        let debug = format!("{:?}", config);
        
        assert!(debug.contains("443"));
        assert!(debug.contains("eth0"));
        assert!(debug.contains("4"));
        assert!(debug.contains("FileConfig"));
    }

    #[test]
    fn debug_format_alternate() {
        let config = FileConfig {
            ports: vec![443],
            interface: "eth0".to_string(),
            queues: 2,
            route_config: None,
            status_socket: None,
        };
        
        let pretty = format!("{:#?}", config);
        
        // Pretty-printed debug spans multiple lines
        assert!(pretty.contains('\n'));
        assert!(pretty.contains("FileConfig"));
    }
}
