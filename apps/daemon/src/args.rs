use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;

#[derive(Debug, Eq, PartialEq)]
pub struct Options {
    pub data_dir: PathBuf,
    pub lmstudio_url: Option<String>,
    pub model_policy: Option<PathBuf>,
}

/// Complete help for the daemon's deliberately small command-line surface.
pub const HELP: &str = concat!(
    "Usage: birdcode-daemon [OPTIONS]\n",
    "\n",
    "Options:\n",
    "  --data-dir PATH       Durable state directory (default: .birdcode)\n",
    "  --lmstudio-url URL    Explicit LM Studio endpoint\n",
    "  --model-policy PATH   Strict JSON policy that pins producer and critic lineages,\n",
    "                        independence domains, and closed root-planning budgets.\n",
    "                        Required for new independently reviewed planning runs.\n",
    "  -h, --help            Show this help\n",
    "\n",
    "Environment:\n",
    "  BIRDCODE_LMSTUDIO_URL and LM_STUDIO_API_TOKEN provide endpoint defaults.\n",
    "  Environment values never define reviewer independence."
);

#[derive(Debug, Eq, PartialEq)]
pub enum ParseOutcome {
    Run(Options),
    Help,
}

#[derive(Debug, Eq, PartialEq)]
pub struct ArgsError(String);

impl fmt::Display for ArgsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ArgsError {}

/// Parses the daemon's deliberately small command-line surface.
///
/// # Errors
///
/// Returns an error for unknown options, non-Unicode option names, or a
/// missing option value.
pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<ParseOutcome, ArgsError> {
    let mut args = args.into_iter();
    let mut data_dir = None;
    let mut lmstudio_url = None;
    let mut model_policy = None;
    while let Some(flag) = args.next() {
        match flag.to_str() {
            Some("--data-dir") => {
                let value = args
                    .next()
                    .ok_or_else(|| ArgsError("--data-dir requires a path".to_owned()))?;
                data_dir = Some(PathBuf::from(value));
            }
            Some("--lmstudio-url") => {
                let value = args
                    .next()
                    .ok_or_else(|| ArgsError("--lmstudio-url requires a URL".to_owned()))?
                    .into_string()
                    .map_err(|_| ArgsError("LM Studio URL must be valid Unicode".to_owned()))?;
                lmstudio_url = Some(value);
            }
            Some("--model-policy") => {
                let value = args
                    .next()
                    .ok_or_else(|| ArgsError("--model-policy requires a path".to_owned()))?;
                if model_policy.replace(PathBuf::from(value)).is_some() {
                    return Err(ArgsError(
                        "--model-policy may only be provided once".to_owned(),
                    ));
                }
            }
            Some("--help" | "-h") => return Ok(ParseOutcome::Help),
            Some(other) => return Err(ArgsError(format!("unknown option: {other}"))),
            None => return Err(ArgsError("options must be valid Unicode".to_owned())),
        }
    }

    let data_dir = data_dir.unwrap_or_else(|| PathBuf::from(".birdcode"));
    Ok(ParseOutcome::Run(Options {
        data_dir,
        lmstudio_url,
        model_policy,
    }))
}

#[cfg(test)]
mod tests {
    use super::{Options, ParseOutcome, parse};
    use std::ffi::OsString;
    use std::path::PathBuf;

    #[test]
    fn defaults_to_workspace_local_state() {
        let outcome = parse(Vec::<OsString>::new()).expect("default options should parse");

        assert_eq!(
            outcome,
            ParseOutcome::Run(Options {
                data_dir: PathBuf::from(".birdcode"),
                lmstudio_url: None,
                model_policy: None,
            })
        );
    }

    #[test]
    fn accepts_an_explicit_data_directory() {
        let outcome = parse(["--data-dir", "/tmp/Bird Code"].map(OsString::from))
            .expect("explicit path should parse");

        assert_eq!(
            outcome,
            ParseOutcome::Run(Options {
                data_dir: PathBuf::from("/tmp/Bird Code"),
                lmstudio_url: None,
                model_policy: None,
            })
        );
    }

    #[test]
    fn accepts_an_explicit_lmstudio_url_without_normalizing_it() {
        let outcome = parse(
            [
                "--data-dir",
                "/tmp/birdcode",
                "--lmstudio-url",
                "http://127.0.0.1:1234/",
            ]
            .map(OsString::from),
        )
        .expect("explicit endpoint should parse");

        assert_eq!(
            outcome,
            ParseOutcome::Run(Options {
                data_dir: PathBuf::from("/tmp/birdcode"),
                lmstudio_url: Some("http://127.0.0.1:1234/".to_owned()),
                model_policy: None,
            })
        );
    }

    #[test]
    fn accepts_an_explicit_model_policy_path() {
        let outcome = parse(["--model-policy", "/tmp/BirdCode policy.json"].map(OsString::from))
            .expect("explicit model policy path should parse");

        assert_eq!(
            outcome,
            ParseOutcome::Run(Options {
                data_dir: PathBuf::from(".birdcode"),
                lmstudio_url: None,
                model_policy: Some(PathBuf::from("/tmp/BirdCode policy.json")),
            })
        );
    }

    #[test]
    fn model_policy_requires_a_path() {
        let error = parse([OsString::from("--model-policy")])
            .expect_err("missing model policy path must fail");

        assert_eq!(error.to_string(), "--model-policy requires a path");
    }

    #[test]
    fn rejects_ambiguous_duplicate_model_policy_paths() {
        let error = parse(
            [
                "--model-policy",
                "/tmp/first.json",
                "--model-policy",
                "/tmp/second.json",
            ]
            .map(OsString::from),
        )
        .expect_err("duplicate model policy paths must fail");

        assert_eq!(
            error.to_string(),
            "--model-policy may only be provided once"
        );
    }

    #[test]
    fn help_describes_explicit_lineages_and_environment_boundary() {
        assert!(super::HELP.contains("--model-policy PATH"));
        assert!(super::HELP.contains("producer and critic lineages"));
        assert!(super::HELP.contains("Required for new independently reviewed planning runs"));
        assert!(super::HELP.contains("Environment values never define reviewer independence"));
    }
}
