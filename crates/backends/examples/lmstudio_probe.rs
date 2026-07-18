use birdcode_backends::{
    LmStudioBackend, LmStudioConfig, Message, ModelBackend, ModelId, SecretToken,
    StructuredInferenceRequest, StructuredOutputSpec,
};
use serde_json::Value;
use std::error::Error;
use std::io;
use url::Url;

const DEFAULT_URL: &str = "http://127.0.0.1:1234/";
const PROBE_PROMPT: &str = include_str!("../../../prompts/lmstudio-connectivity-probe.v1.json");

#[derive(Debug)]
struct Options {
    base_url: Url,
    infer_model: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let Some(options) = parse_options()? else {
        return Ok(());
    };
    let mut config = LmStudioConfig::new(options.base_url);
    config.api_token = std::env::var("LM_STUDIO_API_TOKEN")
        .ok()
        .map(SecretToken::new);
    let backend = LmStudioBackend::new(config)?;

    let catalog = backend.discover_models().await?;
    println!("{}", serde_json::to_string_pretty(&catalog)?);

    if let Some(model) = options.infer_model {
        let request = probe_request(ModelId::new(model)?)?;
        let response = backend.infer_structured(request).await?;
        println!("{}", serde_json::to_string_pretty(&response)?);
    }
    Ok(())
}

fn parse_options() -> Result<Option<Options>, Box<dyn Error>> {
    let mut base_url =
        std::env::var("BIRDCODE_LMSTUDIO_URL").unwrap_or_else(|_| DEFAULT_URL.to_owned());
    let mut infer_model = std::env::var("BIRDCODE_LMSTUDIO_INFER_MODEL").ok();
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--url" => {
                base_url = arguments
                    .next()
                    .ok_or_else(|| io::Error::other("--url requires a value"))?;
            }
            "--infer" => {
                infer_model = Some(
                    arguments
                        .next()
                        .ok_or_else(|| io::Error::other("--infer requires a model ID"))?,
                );
            }
            "--help" | "-h" => {
                println!(
                    "Usage: cargo run -p birdcode-backends --example lmstudio_probe -- [--url URL] [--infer MODEL]\n\
                     Discovery is always read-only. Inference runs only with --infer MODEL or \
                     BIRDCODE_LMSTUDIO_INFER_MODEL."
                );
                return Ok(None);
            }
            unknown => {
                return Err(io::Error::other(format!("unknown argument: {unknown}")).into());
            }
        }
    }
    Ok(Some(Options {
        base_url: Url::parse(&base_url)?,
        infer_model,
    }))
}

fn probe_request(model_id: ModelId) -> Result<StructuredInferenceRequest, Box<dyn Error>> {
    let prompt: Value = serde_json::from_str(PROBE_PROMPT)?;
    require_prompt_metadata(&prompt)?;
    let messages: Vec<Message> = serde_json::from_value(prompt["messages"].clone())?;
    let output = StructuredOutputSpec::new(
        required_string(&prompt["output"]["name"], "output.name")?,
        prompt["output"]["schema"].clone(),
    )?;
    let max_output_tokens = prompt["max_output_tokens"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| io::Error::other("prompt max_output_tokens is not a u32"))?;
    Ok(StructuredInferenceRequest::new(
        model_id,
        messages,
        output,
        max_output_tokens,
    )?)
}

fn require_prompt_metadata(prompt: &Value) -> Result<(), Box<dyn Error>> {
    let _id = required_string(&prompt["id"], "id")?;
    let _role = required_string(&prompt["declared_role"], "declared_role")?;
    if prompt["version"].as_u64().is_none() {
        return Err(io::Error::other("prompt version is missing").into());
    }
    if !prompt["input_schema"].is_object() {
        return Err(io::Error::other("prompt input_schema is missing").into());
    }
    Ok(())
}

fn required_string<'a>(value: &'a Value, field: &str) -> Result<&'a str, Box<dyn Error>> {
    value
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| io::Error::other(format!("prompt {field} is missing")).into())
}
