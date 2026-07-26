use quote::ToTokens as _;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::env;
use std::fs;
use std::path::PathBuf;
use syn::{Attribute, Fields, GenericArgument, Item, PathArguments, Type};

const ROOT_TYPE: &str = "ChildRepositoryExplorerTurnInputV1";

/// Exact outer event vocabulary visible to the frozen repository-explorer-v1
/// compiler. New protocol event variants remain decodable by `EventPayload`,
/// but cannot silently rotate a durable v1 Prepared turn's model input bytes.
const REPOSITORY_EXPLORER_V1_EVENT_PAYLOAD_VARIANTS: &[&str] = &[
    "SessionCreated",
    "UserInput",
    "RunCreated",
    "RunStateChanged",
    "RunClaimed",
    "CancellationRequested",
    "RootPlanningFailed",
    "RootPlanningStageFailed",
    "PlannerInferencePrepared",
    "PlannerInferenceObserved",
    "PlannerInferenceOutcomeUnknown",
    "ReadOperationPrepared",
    "ReadOperationObserved",
    "PlanProposalRejected",
    "PlanProposalAccepted",
    "PlanSemanticReviewAccepted",
    "PlanSemanticReviewRejected",
    "PlannerTurnPreparedV1",
    "PlannerTurnObservedV1",
    "PlannerTurnUnknownV1",
    "PlannerTurnAcceptedV1",
    "PlannerTurnRejectedV1",
    "ReconCompletionGateAcceptedV1",
    "RepositoryWriterLeaseRevoked",
    "RepositorySnapshotCaptureClaimAdoptedV1",
    "RepositorySnapshotCaptureAbandonedV1",
    "RepositorySnapshotLeaseIssued",
    "RepositorySnapshotLeaseReleased",
    "RepositorySnapshotReleaseReconciledV1",
    "RepositoryBrokerEpochActivatedV1",
    "ChildDelegationAuthorized",
    "ChildDelegationAuthorizedV2",
    "ChildWorkOrderIssued",
    "ChildExecutionClaimAdopted",
    "ChildExecutionStarted",
    "ChildModelInferencePrepared",
    "ChildModelInferencePreparedV2",
    "ChildModelInferenceObserved",
    "ChildModelInferenceOutcomeUnknown",
    "ChildToolPrepared",
    "ChildToolObserved",
    "ChildToolOutcomeUnknown",
    "ChildToolPreparedV2",
    "ChildToolObservedV2",
    "ChildToolOutcomeUnknownV2",
    "ChildHandoffCommitted",
    "ChildExecutionFinished",
    "BackendEvent",
    "ArtifactStored",
];

fn contract_enum_variants<'a>(name: &str, value: &'a syn::ItemEnum) -> Vec<&'a syn::Variant> {
    if name != "EventPayload" {
        return value.variants.iter().collect();
    }

    let frozen = value
        .variants
        .iter()
        .filter(|variant| {
            let name = variant.ident.to_string();
            REPOSITORY_EXPLORER_V1_EVENT_PAYLOAD_VARIANTS.contains(&name.as_str())
        })
        .collect::<Vec<_>>();
    let actual = frozen
        .iter()
        .map(|variant| variant.ident.to_string())
        .collect::<Vec<_>>();
    assert_eq!(
        actual, REPOSITORY_EXPLORER_V1_EVENT_PAYLOAD_VARIANTS,
        "the frozen repository-explorer-v1 EventPayload inventory was removed or reordered"
    );
    frozen
}

fn serde_attributes(attributes: &[Attribute]) -> Vec<String> {
    attributes
        .iter()
        .filter(|attribute| attribute.path().is_ident("serde"))
        .map(|attribute| attribute.meta.to_token_stream().to_string())
        .collect()
}

fn serde_string_option(attributes: &[Attribute], option: &str) -> Option<String> {
    for attribute in attributes
        .iter()
        .filter(|attribute| attribute.path().is_ident("serde"))
    {
        let rendered = attribute.meta.to_token_stream().to_string();
        let needle = format!("{option} = \"");
        if let Some(start) = rendered.find(&needle) {
            let value_start = start + needle.len();
            let value_end = rendered[value_start..]
                .find('"')
                .map(|offset| value_start + offset)
                .expect("serde string option must have a closing quote");
            return Some(rendered[value_start..value_end].to_owned());
        }
    }
    None
}

fn snake_case(name: &str) -> String {
    let mut result = String::new();
    for (index, character) in name.chars().enumerate() {
        if character.is_uppercase() {
            if index > 0 {
                result.push('_');
            }
            result.extend(character.to_lowercase());
        } else {
            result.push(character);
        }
    }
    result
}

fn wire_name(name: &str, attributes: &[Attribute], inherited_rename_all: Option<&str>) -> String {
    if let Some(rename) = serde_string_option(attributes, "rename") {
        return rename;
    }
    match inherited_rename_all {
        Some("snake_case") => snake_case(name),
        Some("lowercase") => name.to_lowercase(),
        Some(other) => panic!("unsupported serde rename_all `{other}` in input contract graph"),
        None => name.to_owned(),
    }
}

fn first_generic_type(arguments: &PathArguments) -> &Type {
    let PathArguments::AngleBracketed(arguments) = arguments else {
        panic!("expected generic type arguments");
    };
    arguments
        .args
        .iter()
        .find_map(|argument| match argument {
            GenericArgument::Type(value) => Some(value),
            _ => None,
        })
        .expect("expected one generic type argument")
}

fn generic_types(arguments: &PathArguments) -> Vec<&Type> {
    let PathArguments::AngleBracketed(arguments) = arguments else {
        panic!("expected generic type arguments");
    };
    arguments
        .args
        .iter()
        .filter_map(|argument| match argument {
            GenericArgument::Type(value) => Some(value),
            _ => None,
        })
        .collect()
}

fn collection_shape(
    name: &str,
    arguments: &PathArguments,
    known_types: &BTreeSet<String>,
    uuid_types: &BTreeSet<String>,
    pending: &mut VecDeque<String>,
) -> Value {
    let element = type_shape(
        first_generic_type(arguments),
        known_types,
        uuid_types,
        pending,
    );
    match name {
        "Vec" => json!({"array": element}),
        "BTreeSet" => json!({"ordered_unique_array": element}),
        _ => unreachable!("closed collection match"),
    }
}

fn type_shape(
    value: &Type,
    known_types: &BTreeSet<String>,
    uuid_types: &BTreeSet<String>,
    pending: &mut VecDeque<String>,
) -> Value {
    match value {
        Type::Path(path) => {
            let rendered = path.to_token_stream().to_string();
            if rendered == "serde_json :: Value" {
                return json!({"scalar": "arbitrary_json_value"});
            }
            let segment = path.path.segments.last().expect("type path has a segment");
            let name = segment.ident.to_string();
            match name.as_str() {
                "Option" => json!({
                    "nullable": type_shape(
                        first_generic_type(&segment.arguments),
                        known_types,
                        uuid_types,
                        pending,
                    )
                }),
                "Vec" | "BTreeSet" => {
                    collection_shape(&name, &segment.arguments, known_types, uuid_types, pending)
                }
                "Box" => type_shape(
                    first_generic_type(&segment.arguments),
                    known_types,
                    uuid_types,
                    pending,
                ),
                "BTreeMap" | "HashMap" => {
                    let arguments = generic_types(&segment.arguments);
                    assert_eq!(arguments.len(), 2, "map requires key and value types");
                    json!({
                        "map": {
                            "key": type_shape(arguments[0], known_types, uuid_types, pending),
                            "value": type_shape(arguments[1], known_types, uuid_types, pending),
                        }
                    })
                }
                "DateTime" => json!({
                    "scalar": "chrono_rfc3339_datetime_string",
                    "timezone": "Utc"
                }),
                "String" | "str" => json!({"scalar": "unicode_string"}),
                "bool" => json!({"scalar": "boolean"}),
                "u8" | "u16" | "u32" | "u64" | "u128" | "usize" | "i8" | "i16" | "i32" | "i64"
                | "i128" | "isize" => {
                    json!({"scalar": name})
                }
                "Sha256Digest" => json!({
                    "scalar": "canonical_lowercase_sha256_hex_string",
                    "unicode_scalars": 64
                }),
                "ChildModelVisibleBytesV1" => json!({
                    "scalar": "canonical_rfc4648_base64_string",
                    "decoded_payload": "lossless_arbitrary_bytes"
                }),
                "ChildModelVisibleJsonV1" => json!({
                    "scalar": "canonical_compact_typed_json_utf8_string",
                    "typed_decode_target": type_shape(
                        first_generic_type(&segment.arguments),
                        known_types,
                        uuid_types,
                        pending,
                    ),
                    "validation": "typed_decode_then_byte_identical_reserialize"
                }),
                _ if uuid_types.contains(&name) => json!({
                    "scalar": "lowercase_hyphenated_uuid_string",
                    "rust_type": name
                }),
                _ if known_types.contains(&name) => {
                    pending.push_back(name.clone());
                    json!({"$ref": format!("#/types/{name}")})
                }
                _ => panic!("unresolved model-visible Rust type `{rendered}`"),
            }
        }
        Type::Tuple(tuple) => Value::Array(
            tuple
                .elems
                .iter()
                .map(|element| type_shape(element, known_types, uuid_types, pending))
                .collect(),
        ),
        Type::Array(array) => json!({
            "fixed_array": {
                "element": type_shape(&array.elem, known_types, uuid_types, pending),
                "length_expression": array.len.to_token_stream().to_string()
            }
        }),
        Type::Reference(reference) => type_shape(&reference.elem, known_types, uuid_types, pending),
        other => panic!(
            "unsupported model-visible Rust type `{}`",
            other.to_token_stream()
        ),
    }
}

fn fields_shape(
    fields: &Fields,
    known_types: &BTreeSet<String>,
    uuid_types: &BTreeSet<String>,
    pending: &mut VecDeque<String>,
) -> Vec<Value> {
    fields
        .iter()
        .enumerate()
        .map(|(index, field)| {
            let rust_name = field
                .ident
                .as_ref()
                .map_or_else(|| index.to_string(), ToString::to_string);
            let serde_with = serde_string_option(&field.attrs, "with");
            let wire_type = if matches!(
                serde_with.as_deref(),
                Some("canonical_base64" | "canonical_repository_result_base64")
            ) {
                json!({
                    "scalar": "canonical_rfc4648_base64_string",
                    "decoded_payload": "lossless_arbitrary_bytes"
                })
            } else {
                type_shape(&field.ty, known_types, uuid_types, pending)
            };
            json!({
                "rust_name": rust_name,
                "serde_attributes": serde_attributes(&field.attrs),
                "wire_name": wire_name(&rust_name, &field.attrs, None),
                "wire_type": wire_type
            })
        })
        .collect()
}

#[allow(
    clippy::too_many_lines,
    reason = "the build-time graph walk keeps discovery, closure checking, and canonical emission auditable in one pass"
)]
fn main() {
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=build.rs");

    let source = fs::read_to_string("src/lib.rs").expect("protocol source must be readable");
    let syntax = syn::parse_file(&source).expect("protocol source must parse");
    let mut structs = BTreeMap::new();
    let mut enums = BTreeMap::new();
    let mut aliases = BTreeMap::new();
    let mut uuid_types = BTreeSet::new();
    for item in &syntax.items {
        match item {
            Item::Struct(value) => {
                structs.insert(value.ident.to_string(), value);
            }
            Item::Enum(value) => {
                enums.insert(value.ident.to_string(), value);
            }
            Item::Type(value) => {
                aliases.insert(value.ident.to_string(), value);
            }
            Item::Macro(value)
                if value.mac.path.is_ident("uuid_id") || value.mac.path.is_ident("uuid_v7_id") =>
            {
                uuid_types.insert(value.mac.tokens.to_string().replace(' ', ""));
            }
            _ => {}
        }
    }
    let known_types = structs
        .keys()
        .chain(enums.keys())
        .chain(aliases.keys())
        .cloned()
        .collect::<BTreeSet<_>>();

    let mut pending = VecDeque::from([ROOT_TYPE.to_owned()]);
    let mut types = BTreeMap::<String, Value>::new();
    while let Some(name) = pending.pop_front() {
        if types.contains_key(&name) {
            continue;
        }
        let node = if let Some(value) = structs.get(&name) {
            json!({
                "fields_in_wire_order": fields_shape(
                    &value.fields,
                    &known_types,
                    &uuid_types,
                    &mut pending,
                ),
                "kind": "struct",
                "serde_attributes": serde_attributes(&value.attrs)
            })
        } else if let Some(value) = enums.get(&name) {
            let rename_all = serde_string_option(&value.attrs, "rename_all");
            let variants = contract_enum_variants(&name, value)
                .into_iter()
                .map(|variant| {
                    let rust_name = variant.ident.to_string();
                    json!({
                        "fields_in_wire_order": fields_shape(
                            &variant.fields,
                            &known_types,
                            &uuid_types,
                            &mut pending,
                        ),
                        "rust_name": rust_name,
                        "serde_attributes": serde_attributes(&variant.attrs),
                        "wire_name": wire_name(
                            &rust_name,
                            &variant.attrs,
                            rename_all.as_deref(),
                        )
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "kind": "enum",
                "serde_attributes": serde_attributes(&value.attrs),
                "variants_in_wire_order": variants
            })
        } else if let Some(value) = aliases.get(&name) {
            json!({
                "kind": "alias",
                "wire_type": type_shape(
                    &value.ty,
                    &known_types,
                    &uuid_types,
                    &mut pending,
                )
            })
        } else {
            panic!("missing reachable model-visible type `{name}`");
        };
        types.insert(name, node);
    }

    let types = types.into_iter().collect::<Map<_, _>>();
    let document = json!({
        "contract_kind": "mechanically_generated_recursive_rust_serde_wire_graph",
        "contract_version": 3,
        "external_scalar_contracts_are_inline": true,
        "root_type": ROOT_TYPE,
        "typed_json_wrapper_targets_are_recursive_refs": true,
        "types": types
    });
    let encoded = serde_json::to_vec(&document).expect("input wire graph must encode");
    let output_directory = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set"));
    let output = output_directory.join("child_repository_explorer_v1_input_wire_contract.json");
    fs::write(output, encoded).expect("generated input wire graph must be writable");

    let event_payload = enums
        .get("EventPayload")
        .expect("the frozen explorer input contains EventPayload");
    let gate_patterns = contract_enum_variants("EventPayload", event_payload)
        .into_iter()
        .map(|variant| {
            let identifier = &variant.ident;
            match &variant.fields {
                Fields::Named(_) => quote::quote!(EventPayload::#identifier { .. }),
                Fields::Unnamed(_) => quote::quote!(EventPayload::#identifier(..)),
                Fields::Unit => quote::quote!(EventPayload::#identifier),
            }
        })
        .collect::<Vec<_>>();
    let gate = quote::quote! {
        fn repository_explorer_v1_event_payload_is_frozen(payload: &EventPayload) -> bool {
            matches!(payload, #(#gate_patterns)|*)
        }
    };
    fs::write(
        output_directory.join("repository_explorer_v1_event_payload_gate.rs"),
        gate.to_string(),
    )
    .expect("generated frozen EventPayload gate must be writable");
}
