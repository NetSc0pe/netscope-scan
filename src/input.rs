//! Provides a means to read, parse and hold configuration options for scans.
use clap::{Parser, ValueEnum};
use serde_derive::Deserialize;
use std::fs;
use std::path::PathBuf;

const LOWEST_PORT_NUMBER: u16 = 1;
const TOP_PORT_NUMBER: u16 = 65535;

/// Represents the strategy in which the port scanning will run.
///   - Serial will run from start to end, for example 1 to 1_000.
///   - Random will randomize the order in which ports will be scanned.
#[derive(Deserialize, Debug, ValueEnum, Clone, Copy, PartialEq, Eq)]
pub enum ScanOrder {
    Serial,
    Random,
}

/// Represents the range of ports to be scanned.
#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[cfg(not(tarpaulin_include))]
fn parse_range(input: &str) -> Result<PortRange, String> {
    let range = input
        .split('-')
        .map(str::parse)
        .collect::<Result<Vec<u16>, std::num::ParseIntError>>();

    if range.is_err() {
        return Err(String::from(
            "the range format must be 'start-end'. Example: 1-1000.",
        ));
    }

    match range.unwrap().as_slice() {
        [start, end] => Ok(PortRange {
            start: *start,
            end: *end,
        }),
        _ => Err(String::from(
            "the range format must be 'start-end'. Example: 1-1000.",
        )),
    }
}

#[derive(Parser, Debug, Clone)]
#[command(
    name = "netscope-scan",
    version = env!("CARGO_PKG_VERSION"),
    max_term_width = 120,
    help_template = "{bin} {version}\n{about}\n\nUSAGE:\n    {usage}\n\nOPTIONS:\n{options}",
)]
#[allow(clippy::struct_excessive_bools)]
/// Fast port scanner. Outputs open ports as JSON to stdout.
pub struct Opts {
    /// A comma-delimited list or newline-delimited file of separated CIDRs, IPs, or hosts to be scanned.
    #[arg(short, long, value_delimiter = ',')]
    pub addresses: Vec<String>,

    /// A list of comma separated ports to be scanned. Example: 80,443,8080.
    #[arg(short, long, value_delimiter = ',')]
    pub ports: Option<Vec<u16>>,

    /// A range of ports with format start-end. Example: 1-1000.
    #[arg(short, long, conflicts_with = "ports", value_parser = parse_range)]
    pub range: Option<PortRange>,

    /// Whether to ignore the configuration file or not.
    #[arg(short, long)]
    pub no_config: bool,

    /// Custom path to config file
    #[arg(short, long, value_parser)]
    pub config_path: Option<PathBuf>,

    /// A comma-delimited list or file of DNS resolvers.
    #[arg(long)]
    pub resolver: Option<String>,

    /// The batch size for port scanning, it increases or slows the speed of
    /// scanning. Depends on the open file limit of your OS.  If you do 65535
    /// it will do every port at the same time. Although, your OS may not
    /// support this.
    #[arg(short, long, default_value = "4500")]
    pub batch_size: usize,

    /// The timeout in milliseconds before a port is assumed to be closed.
    #[arg(short, long, default_value = "1500")]
    pub timeout: u32,

    /// The number of tries before a port is assumed to be closed.
    /// If set to 0, it will be corrected to 1.
    #[arg(long, default_value = "1")]
    pub tries: u8,

    /// Automatically ups the ULIMIT with the value you provided.
    #[arg(short, long)]
    pub ulimit: Option<usize>,

    /// The order of scanning to be performed. The "serial" option will
    /// scan ports in ascending order while the "random" option will scan
    /// ports randomly.
    #[arg(long, value_enum, ignore_case = true, default_value = "serial")]
    pub scan_order: ScanOrder,

    /// Use the top 1000 ports.
    #[arg(long)]
    pub top: bool,

    /// A list of comma separated ports to be excluded from scanning. Example: 80,443,8080.
    #[arg(short, long, value_delimiter = ',')]
    pub exclude_ports: Option<Vec<u16>>,

    /// A list of comma separated CIDRs, IPs, or hosts to be excluded from scanning.
    #[arg(short = 'x', long = "exclude-addresses", value_delimiter = ',')]
    pub exclude_addresses: Option<Vec<String>>,

    /// UDP scanning mode, finds UDP ports that send back responses
    #[arg(long)]
    pub udp: bool,

    /// Confirm discovered ports with a second TCP connect using a shorter timeout (milliseconds).
    /// Ports that do not respond within this timeout are dropped from results.
    /// Useful for filtering DROP-firewall false positives. Disabled when absent.
    #[arg(long)]
    pub confirm: Option<u32>,
}

#[cfg(not(tarpaulin_include))]
impl Opts {
    pub fn read() -> Self {
        let mut opts = Opts::parse();

        if opts.ports.is_none() && opts.range.is_none() {
            opts.range = Some(PortRange {
                start: LOWEST_PORT_NUMBER,
                end: TOP_PORT_NUMBER,
            });
        }

        opts
    }

    /// Reads the command line arguments into an Opts struct and merge
    /// values found within the user configuration file.
    pub fn merge(&mut self, config: &Config) {
        if !self.no_config {
            self.merge_required(config);
            self.merge_optional(config);
        }
    }

    fn merge_required(&mut self, config: &Config) {
        macro_rules! merge_required {
            ($($field: ident),+) => {
                $(
                    if let Some(e) = &config.$field {
                        self.$field = e.clone();
                    }
                )+
            }
        }

        merge_required!(addresses, batch_size, timeout, tries, scan_order, udp);
    }

    fn merge_optional(&mut self, config: &Config) {
        macro_rules! merge_optional {
            ($($field: ident),+) => {
                $(
                    if config.$field.is_some() {
                        self.$field = config.$field.clone();
                    }
                )+
            }
        }

        if self.top && config.ports.is_some() {
            self.ports = config.ports.clone();
        }

        merge_optional!(
            range,
            resolver,
            ulimit,
            exclude_ports,
            exclude_addresses,
            confirm
        );
    }
}

impl Default for Opts {
    fn default() -> Self {
        Self {
            addresses: vec![],
            ports: None,
            range: None,
            batch_size: 0,
            timeout: 0,
            tries: 0,
            ulimit: None,
            resolver: None,
            scan_order: ScanOrder::Serial,
            no_config: true,
            top: false,
            config_path: None,
            exclude_ports: None,
            exclude_addresses: None,
            udp: false,
            confirm: None,
        }
    }
}

/// Struct used to deserialize the options specified within our config file.
#[cfg(not(tarpaulin_include))]
#[derive(Debug, Deserialize)]
pub struct Config {
    addresses: Option<Vec<String>>,
    ports: Option<Vec<u16>>,
    range: Option<PortRange>,
    batch_size: Option<usize>,
    timeout: Option<u32>,
    tries: Option<u8>,
    ulimit: Option<usize>,
    resolver: Option<String>,
    scan_order: Option<ScanOrder>,
    exclude_ports: Option<Vec<u16>>,
    exclude_addresses: Option<Vec<String>>,
    udp: Option<bool>,
    confirm: Option<u32>,
}

#[cfg(not(tarpaulin_include))]
#[allow(clippy::doc_link_with_quotes)]
#[allow(clippy::manual_unwrap_or_default)]
impl Config {
    /// Reads the configuration file with TOML format and parses it into a Config struct.
    ///
    /// # Format
    ///
    /// addresses = ["127.0.0.1", "127.0.0.1"]
    /// ports = [80, 443, 8080]
    /// scan_order = "Serial"
    /// exclude_ports = [8080, 9090, 80]
    /// udp = false
    ///
    pub fn read(custom_config_path: Option<PathBuf>) -> Self {
        let mut content = String::new();
        let config_path = custom_config_path.unwrap_or_else(|| {
            let path = default_config_path();
            match path.exists() {
                true => path,
                false => old_default_config_path(),
            }
        });

        if config_path.exists() {
            content = match fs::read_to_string(config_path) {
                Ok(content) => content,
                Err(_) => String::new(),
            }
        }

        let config: Config = match toml::from_str(&content) {
            Ok(config) => config,
            Err(e) => {
                println!("Found {e} in configuration file.\nAborting scan.\n");
                std::process::exit(1);
            }
        };

        config
    }
}

/// Constructs default path to config toml
pub fn default_config_path() -> PathBuf {
    let Some(mut config_path) = dirs::config_dir() else {
        panic!("Could not infer config file path.");
    };
    config_path.push(".netscope-scan.toml");
    config_path
}

/// Returns the deprecated home directory config path used for backwards compatibility.
pub fn old_default_config_path() -> PathBuf {
    let Some(mut config_path) = dirs::home_dir() else {
        panic!("Could not infer config file path.");
    };
    config_path.push(".netscope-scan.toml");
    config_path
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};
    use parameterized::parameterized;

    use super::{Config, Opts, PortRange, ScanOrder};

    impl Config {
        fn default() -> Self {
            Self {
                addresses: Some(vec!["127.0.0.1".to_owned()]),
                ports: None,
                range: None,
                batch_size: Some(25_000),
                timeout: Some(1_000),
                tries: Some(1),
                ulimit: None,
                resolver: None,
                scan_order: Some(ScanOrder::Random),
                exclude_ports: None,
                exclude_addresses: None,
                udp: Some(false),
            }
        }
    }

    #[test]
    fn verify_cli() {
        Opts::command().debug_assert();
    }

    #[parameterized(input = {
        vec!["netscope-scan", "--addresses", "127.0.0.1"],
        vec!["netscope-scan", "--addresses", "127.0.0.1,192.168.0.1"],
    }, expected_addresses = {
        vec!["127.0.0.1".to_owned()],
        vec!["127.0.0.1".to_owned(), "192.168.0.1".to_owned()],
    })]
    fn parse_addresses(input: Vec<&str>, expected_addresses: Vec<String>) {
        let opts = Opts::parse_from(input);
        assert_eq!(expected_addresses, opts.addresses);
    }

    #[test]
    fn opts_no_merge_when_config_is_ignored() {
        let mut opts = Opts::default();
        let config = Config::default();

        opts.merge(&config);

        assert_eq!(opts.addresses, vec![] as Vec<String>);
        assert_eq!(opts.timeout, 0);
        assert_eq!(opts.scan_order, ScanOrder::Serial);
    }

    #[test]
    fn opts_merge_required_arguments() {
        let mut opts = Opts::default();
        let config = Config::default();

        opts.merge_required(&config);

        assert_eq!(opts.addresses, config.addresses.unwrap());
        assert_eq!(opts.timeout, config.timeout.unwrap());
        assert_eq!(opts.scan_order, config.scan_order.unwrap());
    }

    #[test]
    fn opts_merge_optional_arguments() {
        let mut opts = Opts::default();
        let mut config = Config::default();
        config.range = Some(PortRange {
            start: 1,
            end: 1_000,
        });
        config.ulimit = Some(1_000);
        config.resolver = Some("1.1.1.1".to_owned());

        opts.merge_optional(&config);

        assert_eq!(opts.range, config.range);
        assert_eq!(opts.ulimit, config.ulimit);
        assert_eq!(opts.resolver, config.resolver);
    }
}
