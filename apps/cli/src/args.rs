use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    Doctor,
    SessionSmoke,
    Help,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Options {
    pub command: Command,
    pub daemon: Option<PathBuf>,
    pub data_dir: Option<PathBuf>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ArgsError(String);

impl fmt::Display for ArgsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ArgsError {}

pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Options, ArgsError> {
    let mut args = args.into_iter();
    let command = match args.next().and_then(|value| value.into_string().ok()) {
        None => Command::Help,
        Some(value) if value == "doctor" => Command::Doctor,
        Some(value) if value == "session-smoke" => Command::SessionSmoke,
        Some(value) if value == "help" || value == "--help" || value == "-h" => Command::Help,
        Some(value) => return Err(ArgsError(format!("unknown command: {value}"))),
    };

    let mut daemon = None;
    let mut data_dir = None;
    while let Some(flag) = args.next() {
        match flag.to_str() {
            Some("--daemon") => {
                daemon = Some(PathBuf::from(required_value(&mut args, "--daemon")?));
            }
            Some("--data-dir") => {
                data_dir = Some(PathBuf::from(required_value(&mut args, "--data-dir")?));
            }
            Some(other) => return Err(ArgsError(format!("unknown option: {other}"))),
            None => return Err(ArgsError("arguments must be valid Unicode".to_owned())),
        }
    }

    Ok(Options {
        command,
        daemon,
        data_dir,
    })
}

fn required_value(
    args: &mut impl Iterator<Item = OsString>,
    flag: &str,
) -> Result<OsString, ArgsError> {
    args.next()
        .ok_or_else(|| ArgsError(format!("{flag} requires a path")))
}

#[cfg(test)]
mod tests {
    use super::{Command, Options, parse};
    use std::ffi::OsString;
    use std::path::PathBuf;

    #[test]
    fn parses_session_smoke_options() {
        let options = parse(
            [
                "session-smoke",
                "--daemon",
                "/opt/birdcode-daemon",
                "--data-dir",
                "/tmp/birdcode-state",
            ]
            .map(OsString::from),
        )
        .expect("arguments should parse");

        assert_eq!(
            options,
            Options {
                command: Command::SessionSmoke,
                daemon: Some(PathBuf::from("/opt/birdcode-daemon")),
                data_dir: Some(PathBuf::from("/tmp/birdcode-state")),
            }
        );
    }

    #[test]
    fn rejects_unknown_options() {
        let error = parse(["doctor", "--guess"].map(OsString::from))
            .expect_err("unknown options must be rejected");

        assert_eq!(error.to_string(), "unknown option: --guess");
    }
}
