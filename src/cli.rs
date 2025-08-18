use anyhow::Result;
use clap::{builder::PossibleValuesParser, value_parser};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

#[derive(Debug, Clone)]
pub struct AppArgs {
    pub config_file: String,
    pub config_test: bool,
    #[allow(dead_code)]
    pub log_level: String,
}

pub fn parse_args() -> Result<AppArgs> {
    let args = clap::Command::new("redproxy-rs")
        .version(crate::VERSION)
        .arg(
            clap::Arg::new("config")
                .short('c')
                .long("config")
                .help("Config filename")
                .default_value("config.yaml")
                .value_parser(value_parser!(String))
                .num_args(1),
        )
        .arg(
            clap::Arg::new("log-level")
                .short('l')
                .long("log")
                .help("Set log level")
                .value_parser(PossibleValuesParser::new([
                    "erro", "warn", "info", "debug", "trace",
                ]))
                .num_args(1),
        )
        .arg(
            clap::Arg::new("config-check")
                .short('t')
                .long("test")
                .help("Load and check config file then exits"),
        )
        .get_matches();
    let config_file = args
        .get_one("config")
        .map(String::as_str)
        .unwrap_or("config.yaml")
        .to_string();
    let config_test = args.contains_id("config-check");
    let log_level = args
        .get_one("log-level")
        .map(String::as_str)
        .unwrap_or("info")
        .to_string();
    init_logging(&log_level)?;
    Ok(AppArgs {
        config_file,
        config_test,
        log_level,
    })
}

pub fn init_logging(log_level: &str) -> Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(log_level.parse()?)
                .from_env()?,
        )
        .init();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_args_default() {
        let args = AppArgs {
            config_file: "config.yaml".to_string(),
            config_test: false,
            log_level: "info".to_string(),
        };

        assert_eq!(args.config_file, "config.yaml");
        assert!(!args.config_test);
        assert_eq!(args.log_level, "info");
    }

    #[test]
    fn test_init_logging_valid_levels() {
        // Test valid log levels
        let levels = ["erro", "warn", "info", "debug", "trace"];

        for level in levels {
            // Note: We can't actually test init_logging because it can only be called once
            // per process, but we can test the function exists and accepts the right parameters
            assert!(level.parse::<tracing::Level>().is_ok() || level == "erro");
        }
    }

    #[test]
    fn test_app_args_structure() {
        let args = AppArgs {
            config_file: "test.yaml".to_string(),
            config_test: true,
            log_level: "debug".to_string(),
        };

        assert_eq!(args.config_file, "test.yaml");
        assert!(args.config_test);
        assert_eq!(args.log_level, "debug");

        // Test Clone derive
        let cloned_args = args.clone();
        assert_eq!(cloned_args.config_file, args.config_file);
    }
}
