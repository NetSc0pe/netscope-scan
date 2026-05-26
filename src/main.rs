#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::if_not_else)]

use netscope_scan::address::parse_addresses;
use netscope_scan::input::{Config, Opts};
use netscope_scan::port_strategy::PortStrategy;
use netscope_scan::scanner::Scanner;

use futures::executor::block_on;
use serde_json::json;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

#[cfg(unix)]
const DEFAULT_FILE_DESCRIPTORS_LIMIT: usize = 8000;
const AVERAGE_BATCH_SIZE: usize = 3000;

#[macro_use]
extern crate log;

fn main() {
    env_logger::init();

    let mut opts: Opts = Opts::read();
    let config = Config::read(opts.config_path.clone());
    opts.merge(&config);

    debug!("opts: {opts:?}");

    let ips: Vec<IpAddr> = parse_addresses(&opts);

    if ips.is_empty() {
        eprintln!("No IPs could be resolved, aborting scan.");
        std::process::exit(1);
    }

    #[cfg(unix)]
    let batch_size: usize = infer_batch_size(&opts, adjust_ulimit_size(&opts));

    #[cfg(not(unix))]
    let batch_size: usize = AVERAGE_BATCH_SIZE;

    let scanner = Scanner::new(
        &ips,
        batch_size,
        Duration::from_millis(opts.timeout.into()),
        opts.tries,
        true,
        PortStrategy::pick(&opts.range, opts.ports, opts.scan_order),
        true,
        opts.exclude_ports.unwrap_or_default(),
        opts.udp,
    );

    let raw_result = block_on(scanner.run());

    let scan_result = if let Some(confirm_ms) = opts.confirm {
        let confirm_timeout = Duration::from_millis(confirm_ms.into());
        let before = raw_result.len();
        let confirmed = block_on(scanner.confirm(raw_result, confirm_timeout));
        let after = confirmed.len();
        eprintln!("confirm: {before} candidates → {after} confirmed");
        confirmed
    } else {
        raw_result
    };

    let mut ports_per_ip: HashMap<IpAddr, Vec<u16>> = HashMap::new();
    for socket in scan_result {
        ports_per_ip
            .entry(socket.ip())
            .or_insert_with(Vec::new)
            .push(socket.port());
    }

    let result: Vec<serde_json::Value> = ips
        .iter()
        .filter_map(|ip| {
            ports_per_ip
                .get(ip)
                .map(|ports| json!({"ip": ip.to_string(), "ports": ports}))
        })
        .collect();

    println!("{}", serde_json::to_string(&result).unwrap());
}

#[cfg(unix)]
fn adjust_ulimit_size(opts: &Opts) -> usize {
    use rlimit::Resource;
    use std::convert::TryInto;

    if let Some(limit) = opts.ulimit {
        let limit = limit as u64;
        if Resource::NOFILE.set(limit, limit).is_ok() {
            debug!("Automatically increasing ulimit value to {limit}.");
        } else {
            eprintln!("ERROR. Failed to set ulimit value.");
        }
    }

    let (soft, _) = Resource::NOFILE.get().unwrap();
    soft.try_into().unwrap_or(usize::MAX)
}

#[cfg(unix)]
fn infer_batch_size(opts: &Opts, ulimit: usize) -> usize {
    let mut batch_size = opts.batch_size;

    if ulimit < batch_size {
        if ulimit < AVERAGE_BATCH_SIZE {
            batch_size = ulimit / 2;
        } else if ulimit > DEFAULT_FILE_DESCRIPTORS_LIMIT {
            batch_size = AVERAGE_BATCH_SIZE;
        } else {
            batch_size = ulimit - 100;
        }
    }

    batch_size
}

#[cfg(test)]
mod tests {
    use super::Opts;
    #[cfg(unix)]
    use super::{adjust_ulimit_size, infer_batch_size};

    #[test]
    #[cfg(unix)]
    fn batch_size_lowered() {
        let opts = Opts {
            batch_size: 50_000,
            ..Default::default()
        };
        let batch_size = infer_batch_size(&opts, 120);
        assert!(batch_size < opts.batch_size);
    }

    #[test]
    #[cfg(unix)]
    fn batch_size_lowered_average_size() {
        let opts = Opts {
            batch_size: 50_000,
            ..Default::default()
        };
        let batch_size = infer_batch_size(&opts, 9_000);
        assert!(batch_size == 3_000);
    }

    #[test]
    #[cfg(unix)]
    fn batch_size_equals_ulimit_lowered() {
        let opts = Opts {
            batch_size: 50_000,
            ..Default::default()
        };
        let batch_size = infer_batch_size(&opts, 5_000);
        assert!(batch_size == 4_900);
    }

    #[test]
    #[cfg(unix)]
    fn batch_size_adjusted_2000() {
        let opts = Opts {
            batch_size: 50_000,
            ulimit: Some(2_000),
            ..Default::default()
        };
        let batch_size = adjust_ulimit_size(&opts);
        assert!(batch_size == 2_000);
    }

    #[test]
    #[cfg(unix)]
    fn test_high_ulimit() {
        let opts = Opts {
            batch_size: 10,
            ..Default::default()
        };
        let batch_size = infer_batch_size(&opts, 1_000_000);
        assert!(batch_size == opts.batch_size);
    }
}
