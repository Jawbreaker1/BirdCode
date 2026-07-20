use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;

use birdcode_protocol::ROOT_PLANNING_POLICY_V1_INITIAL_PLAN_MAX_OUTPUT_TOKENS as MAX_PLAN_OUTPUT_TOKENS;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    Doctor,
    SessionSmoke,
    Models,
    Plan(PlanOptions),
    Help,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Reasoning {
    Off,
    Low,
    Medium,
    High,
}

impl Reasoning {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanOptions {
    pub model: String,
    pub goal: String,
    pub workspace: Option<PathBuf>,
    pub max_output_tokens: Option<u64>,
    pub max_wall_time_seconds: Option<u64>,
    pub reasoning: Option<Reasoning>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Options {
    pub command: Command,
    pub daemon: Option<PathBuf>,
    pub data_dir: Option<PathBuf>,
    pub model_policy: Option<PathBuf>,
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
    let mut command = parse_command(args.next())?;
    let mut daemon = None;
    let mut data_dir = None;
    let mut model_policy = None;
    let mut model_seen = false;
    let mut goal_seen = false;
    while let Some(flag) = args.next() {
        match flag.to_str() {
            Some("--daemon") => {
                set_once(
                    &mut daemon,
                    PathBuf::from(required_value(&mut args, "--daemon")?),
                    "--daemon",
                )?;
            }
            Some("--data-dir") => {
                set_once(
                    &mut data_dir,
                    PathBuf::from(required_value(&mut args, "--data-dir")?),
                    "--data-dir",
                )?;
            }
            Some("--model-policy") => {
                set_once(
                    &mut model_policy,
                    PathBuf::from(required_value(&mut args, "--model-policy")?),
                    "--model-policy",
                )?;
            }
            Some("--model") => set_plan_string(
                &mut command,
                PlanStringField::Model,
                required_unicode_value(&mut args, "--model")?,
                "--model",
                &mut model_seen,
            )?,
            Some("--goal") => set_plan_string(
                &mut command,
                PlanStringField::Goal,
                required_unicode_value(&mut args, "--goal")?,
                "--goal",
                &mut goal_seen,
            )?,
            Some("--workspace") => {
                let value = PathBuf::from(required_value(&mut args, "--workspace")?);
                let plan = plan_options_mut(&mut command, "--workspace")?;
                set_once(&mut plan.workspace, value, "--workspace")?;
            }
            Some("--max-output-tokens") => {
                let value = required_unicode_value(&mut args, "--max-output-tokens")?;
                let value = parse_positive_limit(&value, "--max-output-tokens")?;
                let plan = plan_options_mut(&mut command, "--max-output-tokens")?;
                set_once(&mut plan.max_output_tokens, value, "--max-output-tokens")?;
            }
            Some("--max-wall-time-seconds") => {
                let value = required_unicode_value(&mut args, "--max-wall-time-seconds")?;
                let value = parse_positive_limit(&value, "--max-wall-time-seconds")?;
                let plan = plan_options_mut(&mut command, "--max-wall-time-seconds")?;
                set_once(
                    &mut plan.max_wall_time_seconds,
                    value,
                    "--max-wall-time-seconds",
                )?;
            }
            Some("--reasoning") => {
                let value = required_unicode_value(&mut args, "--reasoning")?;
                let reasoning = parse_reasoning(&value)?;
                let plan = plan_options_mut(&mut command, "--reasoning")?;
                set_once(&mut plan.reasoning, reasoning, "--reasoning")?;
            }
            Some(other) => return Err(ArgsError(format!("unknown option: {other}"))),
            None => return Err(ArgsError("arguments must be valid Unicode".to_owned())),
        }
    }

    validate_command(&command)?;
    if matches!(command, Command::Plan(_)) && model_policy.is_none() {
        return Err(ArgsError(
            "plan requires an explicit --model-policy PATH for policy-separated semantic review"
                .to_owned(),
        ));
    }

    Ok(Options {
        command,
        daemon,
        data_dir,
        model_policy,
    })
}

fn parse_command(value: Option<OsString>) -> Result<Command, ArgsError> {
    let Some(value) = value else {
        return Ok(Command::Help);
    };
    let value = value
        .into_string()
        .map_err(|_| ArgsError("arguments must be valid Unicode".to_owned()))?;
    match value.as_str() {
        "doctor" => Ok(Command::Doctor),
        "session-smoke" => Ok(Command::SessionSmoke),
        "models" => Ok(Command::Models),
        "plan" => Ok(Command::Plan(PlanOptions {
            model: String::new(),
            goal: String::new(),
            workspace: None,
            max_output_tokens: None,
            max_wall_time_seconds: None,
            reasoning: None,
        })),
        "help" | "--help" | "-h" => Ok(Command::Help),
        _ => Err(ArgsError(format!("unknown command: {value}"))),
    }
}

fn validate_command(command: &Command) -> Result<(), ArgsError> {
    let Command::Plan(plan) = command else {
        return Ok(());
    };
    if plan.model.trim().is_empty() {
        return Err(ArgsError(
            "plan requires an explicit non-empty --model ID".to_owned(),
        ));
    }
    if plan.goal.trim().is_empty() {
        return Err(ArgsError(
            "plan requires an explicit non-empty --goal TEXT".to_owned(),
        ));
    }
    if plan
        .max_output_tokens
        .is_some_and(|limit| limit > u64::from(MAX_PLAN_OUTPUT_TOKENS))
    {
        return Err(ArgsError(format!(
            "--max-output-tokens may not exceed {MAX_PLAN_OUTPUT_TOKENS} for PlanOnly"
        )));
    }
    Ok(())
}

fn parse_positive_limit(value: &str, flag: &str) -> Result<u64, ArgsError> {
    let value = value
        .parse::<u64>()
        .map_err(|_| ArgsError(format!("{flag} requires a positive integer")))?;
    if value == 0 {
        return Err(ArgsError(format!("{flag} requires a positive integer")));
    }
    Ok(value)
}

fn parse_reasoning(value: &str) -> Result<Reasoning, ArgsError> {
    match value {
        "off" => Ok(Reasoning::Off),
        "low" => Ok(Reasoning::Low),
        "medium" => Ok(Reasoning::Medium),
        "high" => Ok(Reasoning::High),
        _ => Err(ArgsError(
            "--reasoning must be one of: off, low, medium, high".to_owned(),
        )),
    }
}

fn required_value(
    args: &mut impl Iterator<Item = OsString>,
    flag: &str,
) -> Result<OsString, ArgsError> {
    args.next()
        .ok_or_else(|| ArgsError(format!("{flag} requires a value")))
}

fn required_unicode_value(
    args: &mut impl Iterator<Item = OsString>,
    flag: &str,
) -> Result<String, ArgsError> {
    required_value(args, flag)?
        .into_string()
        .map_err(|_| ArgsError(format!("{flag} value must be valid Unicode")))
}

fn set_once<T>(slot: &mut Option<T>, value: T, flag: &str) -> Result<(), ArgsError> {
    if slot.replace(value).is_some() {
        return Err(ArgsError(format!("{flag} may only be specified once")));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum PlanStringField {
    Model,
    Goal,
}

fn set_plan_string(
    command: &mut Command,
    field: PlanStringField,
    value: String,
    flag: &str,
    seen: &mut bool,
) -> Result<(), ArgsError> {
    let plan = plan_options_mut(command, flag)?;
    let slot = match field {
        PlanStringField::Model => &mut plan.model,
        PlanStringField::Goal => &mut plan.goal,
    };
    if *seen {
        return Err(ArgsError(format!("{flag} may only be specified once")));
    }
    *seen = true;
    *slot = value;
    Ok(())
}

fn plan_options_mut<'a>(
    command: &'a mut Command,
    flag: &str,
) -> Result<&'a mut PlanOptions, ArgsError> {
    match command {
        Command::Plan(options) => Ok(options),
        _ => Err(ArgsError(format!(
            "{flag} is only valid for the plan command"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::{Command, Options, PlanOptions, Reasoning, parse};
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
                model_policy: None,
            }
        );
    }

    #[test]
    fn rejects_unknown_options() {
        let error = parse(["doctor", "--guess"].map(OsString::from))
            .expect_err("unknown options must be rejected");

        assert_eq!(error.to_string(), "unknown option: --guess");
    }

    #[test]
    fn parses_complete_multilingual_plan_without_changing_bytes() {
        let options = parse(
            [
                "plan",
                "--model",
                "gemma-4-26b-it-qat",
                "--goal",
                "Planera på svenska och 日本語 utan gissningar",
                "--workspace",
                "/tmp/Bird Code",
                "--max-output-tokens",
                "8192",
                "--max-wall-time-seconds",
                "300",
                "--reasoning",
                "high",
                "--data-dir",
                "/tmp/bird-state",
                "--model-policy",
                "/tmp/BirdCode policy.json",
            ]
            .map(OsString::from),
        )
        .expect("plan arguments should parse");

        assert_eq!(
            options,
            Options {
                command: Command::Plan(PlanOptions {
                    model: "gemma-4-26b-it-qat".to_owned(),
                    goal: "Planera på svenska och 日本語 utan gissningar".to_owned(),
                    workspace: Some(PathBuf::from("/tmp/Bird Code")),
                    max_output_tokens: Some(8192),
                    max_wall_time_seconds: Some(300),
                    reasoning: Some(Reasoning::High),
                }),
                daemon: None,
                data_dir: Some(PathBuf::from("/tmp/bird-state")),
                model_policy: Some(PathBuf::from("/tmp/BirdCode policy.json")),
            }
        );
    }

    #[test]
    fn plan_requires_explicit_model_and_goal() {
        let missing_model = parse(
            [
                "plan",
                "--goal",
                "build it",
                "--model-policy",
                "/tmp/policy.json",
            ]
            .map(OsString::from),
        )
        .expect_err("model must be explicit");
        assert_eq!(
            missing_model.to_string(),
            "plan requires an explicit non-empty --model ID"
        );

        let missing_goal = parse(
            ["plan", "--model", "m", "--model-policy", "/tmp/policy.json"].map(OsString::from),
        )
        .expect_err("goal must be explicit");
        assert_eq!(
            missing_goal.to_string(),
            "plan requires an explicit non-empty --goal TEXT"
        );

        let missing_policy = parse(["plan", "--model", "m", "--goal", "goal"].map(OsString::from))
            .expect_err("policy-separated review policy must be explicit");
        assert_eq!(
            missing_policy.to_string(),
            "plan requires an explicit --model-policy PATH for policy-separated semantic review"
        );
    }

    #[test]
    fn plan_rejects_duplicate_and_invalid_bounded_options() {
        let duplicate =
            parse(["plan", "--model", "m", "--model", "n", "--goal", "goal"].map(OsString::from))
                .expect_err("duplicates must fail closed");
        assert_eq!(duplicate.to_string(), "--model may only be specified once");

        let duplicate_after_empty =
            parse(["plan", "--model", "", "--model", "m", "--goal", "goal"].map(OsString::from))
                .expect_err("an empty first occurrence must still count as a duplicate");
        assert_eq!(
            duplicate_after_empty.to_string(),
            "--model may only be specified once"
        );

        let zero = parse(
            [
                "plan",
                "--model",
                "m",
                "--goal",
                "goal",
                "--max-output-tokens",
                "0",
            ]
            .map(OsString::from),
        )
        .expect_err("zero is not a valid budget");
        assert_eq!(
            zero.to_string(),
            "--max-output-tokens requires a positive integer"
        );

        let zero_wall_time = parse(
            [
                "plan",
                "--model",
                "m",
                "--goal",
                "goal",
                "--max-wall-time-seconds",
                "0",
            ]
            .map(OsString::from),
        )
        .expect_err("zero is not a valid wall-time budget");
        assert_eq!(
            zero_wall_time.to_string(),
            "--max-wall-time-seconds requires a positive integer"
        );

        let reasoning = parse(
            [
                "plan",
                "--model",
                "m",
                "--goal",
                "goal",
                "--reasoning",
                "auto",
            ]
            .map(OsString::from),
        )
        .expect_err("unknown reasoning values must fail closed");
        assert_eq!(
            reasoning.to_string(),
            "--reasoning must be one of: off, low, medium, high"
        );

        let reasoning_on = parse(
            [
                "plan",
                "--model",
                "m",
                "--goal",
                "goal",
                "--reasoning",
                "on",
            ]
            .map(OsString::from),
        )
        .expect_err("LM Studio cannot faithfully represent reasoning=on");
        assert_eq!(
            reasoning_on.to_string(),
            "--reasoning must be one of: off, low, medium, high"
        );

        let excessive_output = parse(
            [
                "plan",
                "--model",
                "m",
                "--goal",
                "goal",
                "--max-output-tokens",
                "16385",
            ]
            .map(OsString::from),
        )
        .expect_err("PlanOnly output must respect its compiled hard limit");
        assert_eq!(
            excessive_output.to_string(),
            "--max-output-tokens may not exceed 16384 for PlanOnly"
        );
    }

    #[test]
    fn plan_only_flags_are_rejected_for_other_commands() {
        let error = parse(["models", "--model", "m"].map(OsString::from))
            .expect_err("model selection is not a models-list option");
        assert_eq!(
            error.to_string(),
            "--model is only valid for the plan command"
        );
    }
}
