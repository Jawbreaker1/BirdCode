use crate::canonical;
use crate::manifest::{PromptError, PromptKey, PromptManifest, validate_value};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageRole {
    System,
    User,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    ApplicationPolicy,
    User,
    Repository,
    Tool,
    UntrustedExternal,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    User,
    Repository,
    Tool,
    External,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DataProvenance {
    pub source_kind: SourceKind,
    pub source_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DataSection {
    pub name: String,
    pub trust: TrustLevel,
    pub provenance: DataProvenance,
    pub payload: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PromptInvocation {
    pub sections: Vec<DataSection>,
    pub limits: PromptLimits,
}

impl PromptInvocation {
    #[must_use]
    pub const fn new(sections: Vec<DataSection>) -> Self {
        Self {
            sections,
            limits: PromptLimits::DEFAULT,
        }
    }

    #[must_use]
    pub const fn with_limits(sections: Vec<DataSection>, limits: PromptLimits) -> Self {
        Self { sections, limits }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PromptLimits {
    pub max_suggested_subtasks: u32,
}

impl PromptLimits {
    pub const DEFAULT: Self = Self {
        max_suggested_subtasks: 4,
    };

    #[must_use]
    pub const fn new(max_suggested_subtasks: u32) -> Self {
        Self {
            max_suggested_subtasks,
        }
    }
}

impl Default for PromptLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct CanonicalJson(Value);

impl CanonicalJson {
    #[must_use]
    pub const fn new(value: Value) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn value(&self) -> &Value {
        &self.0
    }

    /// Serializes the payload as deterministic compact JSON.
    ///
    /// # Errors
    ///
    /// Returns an error if the value cannot be serialized.
    pub fn to_compact_string(&self) -> Result<String, serde_json::Error> {
        canonical::encode(&self.0)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "format", content = "value", rename_all = "snake_case")]
pub enum MessageContent {
    Text(String),
    Json(CanonicalJson),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MessageProvenance {
    Manifest { manifest: ManifestProvenance },
    RuntimeConstraints { manifest: ManifestProvenance },
    Data { source: DataProvenance },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestProvenance {
    pub prompt: PromptKey,
    pub content_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledMessage {
    pub role: MessageRole,
    pub trust: TrustLevel,
    pub provenance: MessageProvenance,
    pub content: MessageContent,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompiledPrompt {
    pub manifest: ManifestProvenance,
    pub limits: PromptLimits,
    pub input_sections: Vec<String>,
    pub messages: Vec<CompiledMessage>,
    pub generation_schema: Value,
    pub output_schema: Value,
}

impl CompiledPrompt {
    pub(crate) fn compile(
        manifest: &PromptManifest,
        invocation: &PromptInvocation,
    ) -> Result<Self, PromptError> {
        validate_invocation_boundaries(invocation)?;
        let invocation_value = serde_json::to_value(invocation)?;
        validate_value(&manifest.input_schema, &invocation_value, "prompt input")?;

        let prompt = manifest.key();
        let manifest_provenance = ManifestProvenance {
            prompt,
            content_sha256: manifest.content_sha256()?,
        };
        let mut messages = Vec::with_capacity(invocation.sections.len() + 2);
        messages.push(CompiledMessage {
            role: MessageRole::System,
            trust: TrustLevel::ApplicationPolicy,
            provenance: MessageProvenance::Manifest {
                manifest: manifest_provenance.clone(),
            },
            content: MessageContent::Text(manifest.system_policy.clone()),
        });
        messages.push(CompiledMessage {
            role: MessageRole::System,
            trust: TrustLevel::ApplicationPolicy,
            provenance: MessageProvenance::RuntimeConstraints {
                manifest: manifest_provenance.clone(),
            },
            content: MessageContent::Json(CanonicalJson::new(serde_json::json!({
                "limits": invocation.limits
            }))),
        });
        for section in &invocation.sections {
            messages.push(CompiledMessage {
                role: MessageRole::User,
                trust: section.trust,
                provenance: MessageProvenance::Data {
                    source: section.provenance.clone(),
                },
                content: MessageContent::Json(CanonicalJson::new(serde_json::to_value(section)?)),
            });
        }
        Ok(Self {
            manifest: manifest_provenance,
            limits: invocation.limits,
            input_sections: invocation
                .sections
                .iter()
                .map(|section| section.name.clone())
                .collect(),
            messages,
            generation_schema: specialize_generation_schema(
                &manifest.generation_schema,
                invocation,
            )?,
            output_schema: manifest.output_schema.clone(),
        })
    }

    /// Verifies that this compiled value is an exact rendering of a manifest
    /// and an independently supplied authoritative invocation.
    ///
    /// # Errors
    ///
    /// Returns an error if policy, provenance, messages, schemas, limits, or
    /// section data differ from that invocation. The caller must obtain the
    /// invocation from authoritative runtime state rather than reconstructing
    /// it from this compiled value.
    pub fn validate_against(
        &self,
        manifest: &PromptManifest,
        invocation: &PromptInvocation,
    ) -> Result<(), PromptError> {
        let expected = Self::compile(manifest, invocation)?;
        if &expected == self {
            Ok(())
        } else {
            Err(PromptError::CompiledPromptMismatch(manifest.key()))
        }
    }
}

fn specialize_generation_schema(
    schema: &Value,
    invocation: &PromptInvocation,
) -> Result<Value, PromptError> {
    let mut schema = schema.clone();
    let section_names = invocation
        .sections
        .iter()
        .map(|section| Value::String(section.name.clone()))
        .collect::<Vec<_>>();
    expand_generation_directives(&mut schema, &section_names)?;
    Ok(schema)
}

fn expand_generation_directives(
    value: &mut Value,
    section_names: &[Value],
) -> Result<(), PromptError> {
    match value {
        Value::Array(values) => {
            for value in values {
                expand_generation_directives(value, section_names)?;
            }
        }
        Value::Object(object) => {
            if let Some(directive) = object.remove("x-birdcode-dynamic-enum") {
                if directive.as_str() != Some("input_section_names") {
                    return Err(PromptError::GenerationSchemaDirective(
                        directive.to_string(),
                    ));
                }
                object.insert("enum".to_owned(), Value::Array(section_names.to_vec()));
            }
            for value in object.values_mut() {
                expand_generation_directives(value, section_names)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_invocation_boundaries(invocation: &PromptInvocation) -> Result<(), PromptError> {
    let mut names = BTreeSet::new();
    for section in &invocation.sections {
        if section.name.trim().is_empty() || section.provenance.source_id.trim().is_empty() {
            return Err(PromptError::TrustBoundary {
                section: section.name.clone(),
            });
        }
        if !names.insert(section.name.clone()) {
            return Err(PromptError::DuplicateSection(section.name.clone()));
        }
        let valid_source = matches!(
            (section.trust, section.provenance.source_kind),
            (TrustLevel::User, SourceKind::User)
                | (TrustLevel::Repository, SourceKind::Repository)
                | (TrustLevel::Tool, SourceKind::Tool)
                | (TrustLevel::UntrustedExternal, SourceKind::External)
        );
        if section.trust == TrustLevel::ApplicationPolicy || !valid_source {
            return Err(PromptError::TrustBoundary {
                section: section.name.clone(),
            });
        }
    }
    Ok(())
}
