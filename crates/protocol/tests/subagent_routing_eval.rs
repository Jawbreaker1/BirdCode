use jsonschema::{Retrieve, Uri};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::error::Error;
use std::fs;
use std::path::PathBuf;

const INPUT_SCHEMA_ID: &str =
    "https://birdcode.dev/schemas/evals/subagent-routing-v1/input-envelope.schema.v1.json";
const ROLE_DIGEST: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

#[derive(Clone)]
struct InMemoryRetriever {
    schemas: HashMap<String, Value>,
}

impl Retrieve for InMemoryRetriever {
    fn retrieve(&self, uri: &Uri<String>) -> Result<Value, Box<dyn Error + Send + Sync>> {
        self.schemas
            .get(uri.as_str())
            .cloned()
            .ok_or_else(|| format!("schema not found: {uri}").into())
    }
}

fn eval_path(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../evals/subagent-routing-v1")
        .join(file)
}

fn read_json(file: &str) -> Value {
    let path = eval_path(file);
    let bytes = fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("decode {}: {error}", path.display()))
}

fn usize_value(value: &Value, label: &str) -> usize {
    let number = value
        .as_u64()
        .unwrap_or_else(|| panic!("{label} is not an unsigned integer"));
    usize::try_from(number).unwrap_or_else(|_| panic!("{label} does not fit usize"))
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("expected array")
        .iter()
        .map(|item| item.as_str().expect("expected string").to_owned())
        .collect()
}

fn string_set(value: &Value) -> BTreeSet<String> {
    strings(value).into_iter().collect()
}

fn case_section_ids(case: &Value) -> BTreeSet<String> {
    case["input"]["sections"]
        .as_array()
        .expect("sections are an array")
        .iter()
        .map(|section| section["id"].as_str().expect("section id").to_owned())
        .collect()
}

fn protected_obligation_ids(case: &Value) -> BTreeSet<String> {
    case["input"]["protected_obligations"]
        .as_array()
        .expect("protected obligations are an array")
        .iter()
        .map(|obligation| {
            obligation["obligation_id"]
                .as_str()
                .expect("obligation id")
                .to_owned()
        })
        .collect()
}

fn role_bounds(expected: &Value) -> BTreeMap<String, (usize, usize)> {
    expected["role_cardinality"]
        .as_array()
        .expect("role cardinality is an array")
        .iter()
        .map(|cardinality| {
            (
                cardinality["role_family"]
                    .as_str()
                    .expect("role family")
                    .to_owned(),
                (
                    usize_value(&cardinality["minimum"], "role minimum"),
                    usize_value(&cardinality["maximum"], "role maximum"),
                ),
            )
        })
        .collect()
}

fn graph_is_acyclic(nodes: &BTreeSet<String>, edges: &[(String, String)]) -> bool {
    let mut adjacency = BTreeMap::<String, BTreeSet<String>>::new();
    let mut indegree = nodes
        .iter()
        .map(|node| (node.clone(), 0_usize))
        .collect::<BTreeMap<_, _>>();

    for (from, to) in edges {
        if adjacency
            .entry(from.clone())
            .or_default()
            .insert(to.clone())
        {
            *indegree.entry(to.clone()).or_default() += 1;
        }
    }

    let mut ready = indegree
        .iter()
        .filter_map(|(node, count)| (*count == 0).then_some(node.clone()))
        .collect::<VecDeque<_>>();
    let mut visited = 0_usize;
    while let Some(node) = ready.pop_front() {
        visited += 1;
        if let Some(targets) = adjacency.get(&node) {
            for target in targets {
                let count = indegree.get_mut(target).expect("known graph target");
                *count -= 1;
                if *count == 0 {
                    ready.push_back(target.clone());
                }
            }
        }
    }
    visited == nodes.len()
}

fn graph_has_path(edges: &[(String, String)], start: &str, target: &str) -> bool {
    let mut adjacency = BTreeMap::<&str, Vec<&str>>::new();
    for (from, to) in edges {
        adjacency.entry(from).or_default().push(to);
    }
    let mut visited = BTreeSet::new();
    let mut ready = VecDeque::from([start]);
    while let Some(node) = ready.pop_front() {
        if !visited.insert(node) {
            continue;
        }
        for next in adjacency.get(node).into_iter().flatten() {
            if *next == target {
                return true;
            }
            ready.push_back(next);
        }
    }
    false
}

fn validate_sections(case: &Value, case_id: &str) -> BTreeSet<String> {
    let sections = case["input"]["sections"]
        .as_array()
        .expect("sections are an array");
    let section_ids = case_section_ids(case);
    assert_eq!(
        section_ids.len(),
        sections.len(),
        "duplicate section id in {case_id}"
    );
    for section in sections {
        let trust = section["trust"].as_str().expect("section trust");
        let kind = section["kind"].as_str().expect("section kind");
        let valid_pair = matches!(
            (trust, kind),
            ("user", "request" | "request_variants")
                | ("application_policy", "policy")
                | ("repository_data", "repository")
                | ("runtime_evidence", "evidence" | "acceptance_state")
                | ("model_profile", "model_profile")
                | ("accepted_handoff", "handoff")
        );
        assert!(
            valid_pair,
            "invalid trust/kind pair {trust}/{kind} in {case_id}"
        );
    }
    section_ids
}

fn validate_obligations(
    case: &Value,
    case_id: &str,
    section_ids: &BTreeSet<String>,
) -> BTreeSet<String> {
    let obligations = case["input"]["protected_obligations"]
        .as_array()
        .expect("protected obligations are an array");
    let obligation_ids = protected_obligation_ids(case);
    assert_eq!(
        obligation_ids.len(),
        obligations.len(),
        "duplicate obligation id in {case_id}"
    );
    for obligation in obligations {
        for evidence_ref in strings(&obligation["required_evidence_refs"]) {
            assert!(
                section_ids.contains(&evidence_ref),
                "unknown obligation evidence {evidence_ref} in {case_id}"
            );
        }
    }
    obligation_ids
}

fn validate_role_contract(expected: &Value, case_id: &str, directive: &str) {
    let minimum = usize_value(&expected["child_count"]["minimum"], "minimum child count");
    let maximum = usize_value(&expected["child_count"]["maximum"], "maximum child count");
    assert!(minimum <= maximum, "invalid child bounds in {case_id}");
    assert!(
        (directive == "delegate" && minimum > 0) || (directive != "delegate" && maximum == 0),
        "directive and child bounds disagree in {case_id}"
    );

    let allowed_roles = string_set(&expected["allowed_role_families"]);
    let bounds = role_bounds(expected);
    let bounded_roles = bounds.keys().cloned().collect::<BTreeSet<_>>();
    assert_eq!(
        allowed_roles, bounded_roles,
        "allowed roles and cardinality roles differ in {case_id}"
    );
    let summed_minimum = bounds.values().map(|(lower, _)| lower).sum::<usize>();
    let summed_maximum = bounds.values().map(|(_, upper)| upper).sum::<usize>();
    assert_eq!(
        (summed_minimum, summed_maximum),
        (minimum, maximum),
        "role bounds do not exactly cover child bounds in {case_id}"
    );

    let mut role_edges = Vec::new();
    for edge in expected["required_edges"]
        .as_array()
        .expect("edges are an array")
    {
        let from = edge["from_role_family"]
            .as_str()
            .expect("edge source")
            .to_owned();
        let to = edge["to_role_family"]
            .as_str()
            .expect("edge target")
            .to_owned();
        assert_ne!(from, to, "self-edge in {case_id}");
        let from_maximum = bounds.get(&from).expect("edge source role exists").1;
        let to_maximum = bounds.get(&to).expect("edge target role exists").1;
        let required = usize_value(&edge["minimum"], "edge minimum");
        assert!(
            required <= from_maximum * to_maximum,
            "edge multiplicity is infeasible in {case_id}"
        );
        role_edges.push((from, to));
    }
    assert!(
        graph_is_acyclic(&allowed_roles, &role_edges),
        "role dependency graph is cyclic in {case_id}"
    );
}

fn validate_expected_evidence(expected: &Value, case_id: &str, section_ids: &BTreeSet<String>) {
    for evidence_ref in strings(&expected["required_evidence_refs"]) {
        assert!(
            section_ids.contains(&evidence_ref),
            "unknown expected evidence {evidence_ref} in {case_id}"
        );
    }
}

fn validate_finish_contract(
    expected: &Value,
    case_id: &str,
    directive: &str,
    section_ids: &BTreeSet<String>,
    obligation_ids: &BTreeSet<String>,
) {
    if directive == "finish" {
        let claims = expected["required_finish_claims"]
            .as_array()
            .expect("finish case requires exact claim bindings");
        assert!(!claims.is_empty(), "finish claims are empty in {case_id}");
        let claimed = claims
            .iter()
            .map(|claim| claim["obligation_id"].as_str().expect("claim obligation"))
            .collect::<BTreeSet<_>>();
        let protected = obligation_ids.iter().map(String::as_str).collect();
        assert_eq!(
            claimed, protected,
            "finish claims do not exactly cover protected obligations in {case_id}"
        );
        for claim in claims {
            for evidence_ref in strings(&claim["evidence_refs"]) {
                assert!(
                    section_ids.contains(&evidence_ref),
                    "unknown finish evidence {evidence_ref} in {case_id}"
                );
            }
        }
    } else {
        assert!(
            expected.get("required_finish_claims").is_none(),
            "non-finish case carries finish claims in {case_id}"
        );
    }
}

fn validate_metamorphic_contract(case: &Value, expected: &Value, case_id: &str) {
    if let Some(metamorphic) = expected.get("metamorphic") {
        let variants = case["input"]["sections"]
            .as_array()
            .expect("sections are an array")
            .iter()
            .find(|section| section["kind"] == "request_variants")
            .expect("metamorphic case has request variants")["payload"]
            .as_array()
            .expect("request variants are an array");
        assert_eq!(
            usize_value(&metamorphic["group_size"], "group size"),
            variants.len(),
            "metamorphic group size mismatch in {case_id}"
        );
    }
}

fn validate_case_contract(case: &Value, case_ids: &mut BTreeSet<String>) {
    let case_id = case["id"].as_str().expect("case id is a string");
    assert!(
        case_ids.insert(case_id.to_owned()),
        "duplicate case id: {case_id}"
    );
    assert_eq!(case["input"]["case_id"], case["id"]);

    let section_ids = validate_sections(case, case_id);
    let obligation_ids = validate_obligations(case, case_id, &section_ids);
    let expected = &case["expected"];
    let directives = strings(&expected["allowed_directives"]);
    assert_eq!(
        directives.len(),
        1,
        "v1 fixtures require one unambiguous directive in {case_id}"
    );
    validate_role_contract(expected, case_id, &directives[0]);
    validate_expected_evidence(expected, case_id, &section_ids);
    validate_finish_contract(
        expected,
        case_id,
        &directives[0],
        &section_ids,
        &obligation_ids,
    );
    validate_metamorphic_contract(case, expected, case_id);
}

fn choose_execution_shape(role: &str, allowed: &BTreeSet<String>) -> String {
    if role.ends_with("reviewer") && allowed.contains("independent_review") {
        "independent_review".to_owned()
    } else if role == "candidate_implementer" && allowed.contains("independent_candidates") {
        "independent_candidates".to_owned()
    } else if allowed.contains("independent_parallel") {
        "independent_parallel".to_owned()
    } else if allowed.contains("ordered") {
        "ordered".to_owned()
    } else {
        allowed
            .iter()
            .next()
            .expect("delegate execution shape")
            .clone()
    }
}

struct DelegateWitnessContext<'a> {
    case_id: &'a str,
    expected: &'a Value,
    evidence_refs: &'a [String],
    obligation_ids: &'a [String],
    allowed_shapes: BTreeSet<String>,
    required_isolation: Vec<String>,
    required_independence: Vec<String>,
    handoff_properties: Vec<String>,
    overall_authority: &'a str,
}

fn delegate_witness_context<'a>(
    case_id: &'a str,
    expected: &'a Value,
    evidence_refs: &'a [String],
    obligation_ids: &'a [String],
) -> DelegateWitnessContext<'a> {
    DelegateWitnessContext {
        case_id,
        expected,
        evidence_refs,
        obligation_ids,
        allowed_shapes: string_set(&expected["allowed_execution_shapes"]),
        required_isolation: strings(&expected["required_isolation"]),
        required_independence: strings(&expected["required_independence"]),
        handoff_properties: strings(&expected["required_handoff_properties"]),
        overall_authority: expected["authority_ceiling"]
            .as_str()
            .expect("authority ceiling"),
    }
}

fn build_delegate_children(
    context: &DelegateWitnessContext<'_>,
) -> (Vec<Value>, BTreeMap<String, Vec<usize>>) {
    let mut children = Vec::new();
    let mut children_by_role = BTreeMap::<String, Vec<usize>>::new();
    for cardinality in context.expected["role_cardinality"]
        .as_array()
        .expect("role cardinality")
    {
        let role = cardinality["role_family"].as_str().expect("role family");
        let count = usize_value(&cardinality["minimum"], "minimum");
        for ordinal in 1..=count {
            let reviewer = role.ends_with("reviewer");
            let authority = if reviewer && context.overall_authority == "workspace_write" {
                "read_only"
            } else {
                context.overall_authority
            };
            let independence = if reviewer {
                context.required_independence.clone()
            } else {
                Vec::new()
            };
            let index = children.len();
            children.push(json!({
                "local_child_ref": format!("child:{role}:{ordinal}"),
                "role_definition_ref": {
                    "id": format!("role:{role}"),
                    "version": "1",
                    "digest": ROLE_DIGEST,
                    "role_family": role
                },
                "semantic_purpose": format!("Perform the bounded {role} responsibility."),
                "objective": format!("Produce the typed {role} handoff for {}.", context.case_id),
                "depends_on": [],
                "authority_ceiling": authority,
                "execution_shape": choose_execution_shape(role, &context.allowed_shapes),
                "context_policy": "exact_manifest",
                "isolation": context.required_isolation,
                "independence": independence,
                "budget": {
                    "max_model_calls": 4,
                    "max_output_tokens": 8192,
                    "max_tool_calls": 32,
                    "max_wall_time_ms": 600_000
                },
                "handoff_schema_id": format!("handoff:{role}:v1"),
                "handoff_properties": context.handoff_properties,
                "protected_obligation_ids": context.obligation_ids,
                "acceptance_criteria": ["Satisfy the typed handoff and cited evidence contract."],
                "evidence_refs": context.evidence_refs
            }));
            children_by_role
                .entry(role.to_owned())
                .or_default()
                .push(index);
        }
    }
    (children, children_by_role)
}

fn add_required_dependencies(
    expected: &Value,
    children: &mut [Value],
    children_by_role: &BTreeMap<String, Vec<usize>>,
) {
    for edge in expected["required_edges"]
        .as_array()
        .expect("required edges")
    {
        let from = edge["from_role_family"].as_str().expect("edge source");
        let to = edge["to_role_family"].as_str().expect("edge target");
        let required = usize_value(&edge["minimum"], "edge minimum");
        let sources = children_by_role.get(from).expect("source children");
        let targets = children_by_role.get(to).expect("target children");
        let pairs = sources
            .iter()
            .flat_map(|source| targets.iter().map(move |target| (*source, *target)))
            .take(required)
            .collect::<Vec<_>>();
        assert_eq!(pairs.len(), required, "witness edge feasibility");
        for (source, target) in pairs {
            let source_ref = children[source]["local_child_ref"].clone();
            children[target]["depends_on"]
                .as_array_mut()
                .expect("depends_on array")
                .push(source_ref);
        }
    }
}

fn ensure_witness_independence(children: &mut [Value], required: &[String]) {
    if !required.is_empty()
        && children.iter().all(|child| {
            child["independence"]
                .as_array()
                .expect("independence")
                .is_empty()
        })
    {
        children[0]["independence"] = json!(required);
    }
}

fn build_parallel_sets(children: &[Value]) -> Vec<Value> {
    let parallel = children
        .iter()
        .filter(|child| {
            matches!(
                child["execution_shape"].as_str(),
                Some("independent_parallel" | "independent_candidates")
            ) && child["depends_on"]
                .as_array()
                .expect("depends_on")
                .is_empty()
        })
        .map(|child| child["local_child_ref"].clone())
        .collect::<Vec<_>>();
    (parallel.len() >= 2)
        .then_some(Value::Array(parallel))
        .into_iter()
        .collect()
}

fn build_delegate_proposal(context: &DelegateWitnessContext<'_>) -> Value {
    let (mut children, children_by_role) = build_delegate_children(context);
    add_required_dependencies(context.expected, &mut children, &children_by_role);
    ensure_witness_independence(&mut children, &context.required_independence);
    let parallel_sets = build_parallel_sets(&children);
    let integration_owner = children
        .iter()
        .find(|child| child["role_definition_ref"]["role_family"] == "integration_agent")
        .map_or_else(|| json!("root"), |child| child["local_child_ref"].clone());
    json!({
        "proposal_id": format!("proposal:{}", context.case_id),
        "protected_obligation_ids": context.obligation_ids,
        "children": children,
        "parallel_sets": parallel_sets,
        "wait_policy": "all",
        "integration_owner": integration_owner
    })
}

struct WitnessBranch {
    direct_work_order_refs: Vec<Value>,
    direct_authority_ceiling: Value,
    spawn_proposal: Value,
    clarification_requests: Vec<Value>,
    escalation_requests: Vec<Value>,
    finish_claims: Vec<Value>,
}

impl WitnessBranch {
    fn empty() -> Self {
        Self {
            direct_work_order_refs: Vec::new(),
            direct_authority_ceiling: Value::Null,
            spawn_proposal: Value::Null,
            clarification_requests: Vec::new(),
            escalation_requests: Vec::new(),
            finish_claims: Vec::new(),
        }
    }
}

fn build_branch_witness(
    case_id: &str,
    directive: &str,
    expected: &Value,
    evidence_refs: &[String],
    obligation_ids: &[String],
) -> WitnessBranch {
    let mut branch = WitnessBranch::empty();
    match directive {
        "execute" => {
            branch
                .direct_work_order_refs
                .push(json!("work-order:direct"));
            branch.direct_authority_ceiling = expected["authority_ceiling"].clone();
        }
        "delegate" => {
            let context =
                delegate_witness_context(case_id, expected, evidence_refs, obligation_ids);
            branch.spawn_proposal = build_delegate_proposal(&context);
        }
        "clarify" => {
            branch.clarification_requests = strings(&expected["required_clarification_topics"])
                .into_iter()
                .map(|topic_id| {
                    json!({
                        "topic_id": topic_id,
                        "question": "Provide the missing material product decision.",
                        "evidence_refs": evidence_refs
                    })
                })
                .collect();
        }
        "escalate" => {
            branch.escalation_requests = strings(&expected["required_escalation_kinds"])
                .into_iter()
                .map(|kind| {
                    json!({
                        "kind": kind,
                        "request": "Provide the exact missing admission resource or authority.",
                        "evidence_refs": evidence_refs
                    })
                })
                .collect();
        }
        "finish" => branch.finish_claims.clone_from(
            expected["required_finish_claims"]
                .as_array()
                .expect("finish claims"),
        ),
        other => panic!("unsupported directive {other}"),
    }
    branch
}

fn activation_source_refs(kind: &str, evidence_refs: &[String]) -> Vec<String> {
    match kind {
        "none" => Vec::new(),
        "explicit_user_request" => evidence_refs
            .iter()
            .filter(|evidence_ref| {
                matches!(evidence_ref.as_str(), "user_request" | "semantic_variants")
            })
            .cloned()
            .collect(),
        _ => evidence_refs
            .iter()
            .filter(|evidence_ref| evidence_ref.as_str() == "trusted_policy")
            .cloned()
            .collect(),
    }
}

fn build_contract_witness(case: &Value) -> Value {
    let case_id = case["id"].as_str().expect("case id");
    let expected = &case["expected"];
    let directive = expected["allowed_directives"][0]
        .as_str()
        .expect("directive");
    let evidence_refs = strings(&expected["required_evidence_refs"]);
    let obligation_ids = protected_obligation_ids(case)
        .into_iter()
        .collect::<Vec<_>>();
    let basis = evidence_refs
        .iter()
        .map(|evidence_ref| {
            json!({
                "evidence_ref": evidence_ref,
                "rationale": "This typed evidence contributes to the routing decision."
            })
        })
        .collect::<Vec<_>>();
    let requested_constraints = strings(&expected["required_constraint_ids"])
        .into_iter()
        .map(|constraint_id| {
            json!({
                "constraint_id": constraint_id,
                "evidence_refs": [evidence_refs.first().expect("case evidence")]
            })
        })
        .collect::<Vec<_>>();
    let decision_reasons = strings(&expected["required_decision_reason_ids"])
        .into_iter()
        .map(|code| json!({"code": code, "evidence_refs": evidence_refs}))
        .collect::<Vec<_>>();
    let activation_kind = expected["activation_source"]
        .as_str()
        .expect("activation source");
    let branch = build_branch_witness(
        case_id,
        directive,
        expected,
        &evidence_refs,
        &obligation_ids,
    );

    json!({
        "schema_version": 1,
        "case_id": case_id,
        "causal_binding": case["input"]["causal_binding"].clone(),
        "activation_source": {
            "kind": activation_kind,
            "source_refs": activation_source_refs(activation_kind, &evidence_refs)
        },
        "directive": directive,
        "basis": basis,
        "decision_reasons": decision_reasons,
        "requested_constraints": requested_constraints,
        "protected_obligation_ids": obligation_ids,
        "adaptation_ids": expected.get("required_adaptations").map(strings).unwrap_or_default(),
        "direct_work_order_refs": branch.direct_work_order_refs,
        "direct_authority_ceiling": branch.direct_authority_ceiling,
        "spawn_proposal": branch.spawn_proposal,
        "clarification_requests": branch.clarification_requests,
        "escalation_requests": branch.escalation_requests,
        "finish_claims": branch.finish_claims
    })
}

fn authority_rank(authority: &str) -> usize {
    match authority {
        "none" => 0,
        "read_only" => 1,
        "workspace_write" => 2,
        other => panic!("unknown authority {other}"),
    }
}

fn ensure(condition: bool, message: impl Into<String>) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

struct ScoreContext<'a> {
    expected: &'a Value,
    known_evidence: BTreeSet<String>,
    known_obligations: BTreeSet<String>,
}

impl<'a> ScoreContext<'a> {
    fn for_case(case: &'a Value) -> Self {
        Self {
            expected: &case["expected"],
            known_evidence: case_section_ids(case),
            known_obligations: protected_obligation_ids(case),
        }
    }
}

fn score_activation(
    case: &Value,
    output: &Value,
    context: &ScoreContext<'_>,
) -> Result<(), String> {
    ensure(output["case_id"] == case["id"], "case id mismatch")?;
    ensure(
        output["causal_binding"] == case["input"]["causal_binding"],
        "stale or foreign causal binding",
    )?;
    ensure(
        output["activation_source"]["kind"] == context.expected["activation_source"],
        "activation source mismatch",
    )?;
    let sections_by_id = case["input"]["sections"]
        .as_array()
        .expect("sections")
        .iter()
        .map(|section| {
            (
                section["id"].as_str().expect("section id"),
                section["trust"].as_str().expect("section trust"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let activation_kind = output["activation_source"]["kind"]
        .as_str()
        .ok_or("activation kind")?;
    for source_ref in strings(&output["activation_source"]["source_refs"]) {
        ensure(
            context.known_evidence.contains(&source_ref),
            format!("unknown activation source {source_ref}"),
        )?;
        let source_trust = sections_by_id
            .get(source_ref.as_str())
            .copied()
            .ok_or("activation source trust")?;
        let valid_trust = match activation_kind {
            "explicit_user_request" => source_trust == "user",
            "applicable_project_instruction"
            | "applicable_skill_instruction"
            | "policy_permitted_proactive" => source_trust == "application_policy",
            _ => false,
        };
        ensure(valid_trust, "activation source has incompatible trust")?;
    }
    Ok(())
}

fn score_basis(output: &Value, context: &ScoreContext<'_>) -> Result<(), String> {
    let mut basis_refs = BTreeSet::new();
    for basis in output["basis"].as_array().ok_or("basis is not an array")? {
        let evidence_ref = basis["evidence_ref"].as_str().ok_or("basis evidence ref")?;
        ensure(
            context.known_evidence.contains(evidence_ref),
            format!("unknown basis evidence {evidence_ref}"),
        )?;
        basis_refs.insert(evidence_ref.to_owned());
    }
    for required in strings(&context.expected["required_evidence_refs"]) {
        ensure(
            basis_refs.contains(&required),
            format!("missing required evidence {required}"),
        )?;
    }
    Ok(())
}

fn score_decision_reasons(output: &Value, context: &ScoreContext<'_>) -> Result<(), String> {
    let mut decision_reason_ids = BTreeSet::new();
    for reason in output["decision_reasons"]
        .as_array()
        .ok_or("decision reasons are not an array")?
    {
        let reason_id = reason["code"].as_str().ok_or("decision reason id")?;
        ensure(
            decision_reason_ids.insert(reason_id.to_owned()),
            format!("duplicate decision reason {reason_id}"),
        )?;
        for evidence_ref in strings(&reason["evidence_refs"]) {
            ensure(
                context.known_evidence.contains(&evidence_ref),
                format!("unknown decision evidence {evidence_ref}"),
            )?;
        }
    }
    for required in strings(&context.expected["required_decision_reason_ids"]) {
        ensure(
            decision_reason_ids.contains(&required),
            format!("missing decision reason {required}"),
        )?;
    }
    Ok(())
}

fn score_requested_constraints(
    output: &Value,
    context: &ScoreContext<'_>,
) -> Result<BTreeSet<String>, String> {
    let mut requested_constraint_ids = BTreeSet::new();
    for coverage in output["requested_constraints"]
        .as_array()
        .ok_or("requested constraints is not an array")?
    {
        let constraint_id = coverage["constraint_id"].as_str().ok_or("constraint id")?;
        ensure(
            requested_constraint_ids.insert(constraint_id.to_owned()),
            format!("duplicate requested constraint {constraint_id}"),
        )?;
        for evidence_ref in strings(&coverage["evidence_refs"]) {
            ensure(
                context.known_evidence.contains(&evidence_ref),
                format!("unknown constraint evidence {evidence_ref}"),
            )?;
        }
    }
    for required in strings(&context.expected["required_constraint_ids"]) {
        ensure(
            requested_constraint_ids.contains(&required),
            format!("missing requested constraint {required}"),
        )?;
    }
    Ok(requested_constraint_ids)
}

fn score_obligations_and_adaptations(
    output: &Value,
    context: &ScoreContext<'_>,
) -> Result<(), String> {
    ensure(
        string_set(&output["protected_obligation_ids"]) == context.known_obligations,
        "protected obligation set changed",
    )?;
    let adaptations = string_set(&output["adaptation_ids"]);
    for required in context
        .expected
        .get("required_adaptations")
        .map(strings)
        .unwrap_or_default()
    {
        ensure(
            adaptations.contains(&required),
            format!("missing required adaptation {required}"),
        )?;
    }
    Ok(())
}

struct DelegateFacts {
    refs: BTreeSet<String>,
    roles_by_ref: BTreeMap<String, String>,
    role_counts: BTreeMap<String, usize>,
    isolation: BTreeSet<String>,
    independence: BTreeSet<String>,
    handoff_properties: BTreeSet<String>,
    delegated_obligations: BTreeSet<String>,
    maximum_authority: usize,
}

fn collect_delegate_facts(
    children: &[Value],
    context: &ScoreContext<'_>,
) -> Result<DelegateFacts, String> {
    let allowed_roles = string_set(&context.expected["allowed_role_families"]);
    let allowed_shapes = string_set(&context.expected["allowed_execution_shapes"]);
    let mut facts = DelegateFacts {
        refs: BTreeSet::new(),
        roles_by_ref: BTreeMap::new(),
        role_counts: BTreeMap::new(),
        isolation: BTreeSet::new(),
        independence: BTreeSet::new(),
        handoff_properties: BTreeSet::new(),
        delegated_obligations: BTreeSet::new(),
        maximum_authority: 0,
    };
    for child in children {
        let local_ref = child["local_child_ref"].as_str().ok_or("child ref")?;
        ensure(
            facts.refs.insert(local_ref.to_owned()),
            "duplicate child ref",
        )?;
        let role = child["role_definition_ref"]["role_family"]
            .as_str()
            .ok_or("child role")?;
        ensure(
            allowed_roles.contains(role),
            format!("unallowed role {role}"),
        )?;
        facts
            .roles_by_ref
            .insert(local_ref.to_owned(), role.to_owned());
        *facts.role_counts.entry(role.to_owned()).or_default() += 1;
        let shape = child["execution_shape"].as_str().ok_or("execution shape")?;
        ensure(
            allowed_shapes.contains(shape),
            format!("unallowed execution shape {shape}"),
        )?;
        facts.maximum_authority = facts.maximum_authority.max(authority_rank(
            child["authority_ceiling"]
                .as_str()
                .ok_or("child authority")?,
        ));
        facts.isolation.extend(strings(&child["isolation"]));
        facts.independence.extend(strings(&child["independence"]));
        facts
            .handoff_properties
            .extend(strings(&child["handoff_properties"]));
        for obligation in strings(&child["protected_obligation_ids"]) {
            ensure(
                context.known_obligations.contains(&obligation),
                format!("child invented obligation {obligation}"),
            )?;
            facts.delegated_obligations.insert(obligation);
        }
        for evidence_ref in strings(&child["evidence_refs"]) {
            ensure(
                context.known_evidence.contains(&evidence_ref),
                format!("child cites unknown evidence {evidence_ref}"),
            )?;
        }
    }
    Ok(facts)
}

fn score_delegate_facts(facts: &DelegateFacts, context: &ScoreContext<'_>) -> Result<(), String> {
    ensure(
        facts.delegated_obligations == context.known_obligations,
        "children dropped protected obligations",
    )?;
    for (role, (lower, upper)) in role_bounds(context.expected) {
        let actual = facts.role_counts.get(&role).copied().unwrap_or_default();
        ensure(
            (lower..=upper).contains(&actual),
            format!("role cardinality mismatch for {role}"),
        )?;
    }
    let expected_authority = context.expected["authority_ceiling"]
        .as_str()
        .expect("expected authority");
    ensure(
        facts.maximum_authority == authority_rank(expected_authority),
        "delegated authority ceiling mismatch",
    )?;
    for required in strings(&context.expected["required_isolation"]) {
        ensure(
            facts.isolation.contains(&required),
            format!("missing isolation {required}"),
        )?;
    }
    for required in strings(&context.expected["required_independence"]) {
        ensure(
            facts.independence.contains(&required),
            format!("missing independence {required}"),
        )?;
    }
    for required in strings(&context.expected["required_handoff_properties"]) {
        ensure(
            facts.handoff_properties.contains(&required),
            format!("missing handoff property {required}"),
        )?;
    }
    Ok(())
}

fn collect_child_edges(
    children: &[Value],
    refs: &BTreeSet<String>,
) -> Result<Vec<(String, String)>, String> {
    let mut edges = Vec::new();
    for child in children {
        let target = child["local_child_ref"].as_str().expect("target ref");
        for source in strings(&child["depends_on"]) {
            ensure(
                refs.contains(&source),
                format!("unknown dependency {source}"),
            )?;
            ensure(source != target, "child self-dependency")?;
            edges.push((source, target.to_owned()));
        }
    }
    ensure(
        graph_is_acyclic(refs, &edges),
        "concrete child graph is cyclic",
    )?;
    Ok(edges)
}

fn score_required_edges(
    edges: &[(String, String)],
    roles_by_ref: &BTreeMap<String, String>,
    expected: &Value,
) -> Result<(), String> {
    for requirement in expected["required_edges"]
        .as_array()
        .expect("required edges")
    {
        let from = requirement["from_role_family"].as_str().expect("from role");
        let to = requirement["to_role_family"].as_str().expect("to role");
        let actual = edges
            .iter()
            .filter(|(source, target)| {
                roles_by_ref.get(source).map(String::as_str) == Some(from)
                    && roles_by_ref.get(target).map(String::as_str) == Some(to)
            })
            .count();
        let required = usize_value(&requirement["minimum"], "edge minimum");
        ensure(
            actual >= required,
            format!("missing required {from}->{to} dependency"),
        )?;
    }
    Ok(())
}

fn score_parallel_sets(
    proposal: &serde_json::Map<String, Value>,
    children: &[Value],
    facts: &DelegateFacts,
    edges: &[(String, String)],
) -> Result<(), String> {
    let parallel_sets = proposal["parallel_sets"]
        .as_array()
        .ok_or("parallel sets")?;
    for parallel_set in parallel_sets {
        let members = strings(parallel_set);
        for member in &members {
            ensure(
                facts.refs.contains(member),
                format!("unknown parallel member {member}"),
            )?;
        }
        for (index, left) in members.iter().enumerate() {
            for right in members.iter().skip(index + 1) {
                ensure(
                    !graph_has_path(edges, left, right) && !graph_has_path(edges, right, left),
                    "causally dependent children placed in one parallel set",
                )?;
            }
        }
    }
    let parallel_shape_present = children.iter().any(|child| {
        matches!(
            child["execution_shape"].as_str(),
            Some("independent_parallel" | "independent_candidates")
        )
    });
    ensure(
        !parallel_shape_present || !parallel_sets.is_empty(),
        "parallel execution shape lacks a concrete parallel set",
    )
}

fn score_reviewer_authority(
    children: &[Value],
    requested_constraint_ids: &BTreeSet<String>,
) -> Result<(), String> {
    if requested_constraint_ids.contains("reviewer_read_only") {
        for child in children.iter().filter(|child| {
            child["role_definition_ref"]["role_family"]
                .as_str()
                .is_some_and(|role| role.ends_with("reviewer"))
        }) {
            ensure(
                child["authority_ceiling"] == "read_only",
                "reviewer is not read-only",
            )?;
        }
    }
    Ok(())
}

fn score_delegate(
    output: &Value,
    context: &ScoreContext<'_>,
    requested_constraint_ids: &BTreeSet<String>,
) -> Result<(), String> {
    let proposal = output["spawn_proposal"]
        .as_object()
        .ok_or("missing spawn proposal")?;
    ensure(
        string_set(&proposal["protected_obligation_ids"]) == context.known_obligations,
        "spawn proposal dropped protected obligations",
    )?;
    let children = proposal["children"].as_array().ok_or("children")?;
    let minimum = usize_value(&context.expected["child_count"]["minimum"], "minimum");
    let maximum = usize_value(&context.expected["child_count"]["maximum"], "maximum");
    ensure(
        (minimum..=maximum).contains(&children.len()),
        "child count outside expected bounds",
    )?;
    let facts = collect_delegate_facts(children, context)?;
    score_delegate_facts(&facts, context)?;
    let edges = collect_child_edges(children, &facts.refs)?;
    score_required_edges(&edges, &facts.roles_by_ref, context.expected)?;
    score_parallel_sets(proposal, children, &facts, &edges)?;
    let integration_owner = proposal["integration_owner"]
        .as_str()
        .ok_or("integration owner")?;
    ensure(
        integration_owner == "root" || facts.refs.contains(integration_owner),
        "unknown integration owner",
    )?;
    score_reviewer_authority(children, requested_constraint_ids)
}

fn score_request_evidence(
    requests: &[Value],
    known_evidence: &BTreeSet<String>,
    label: &str,
) -> Result<(), String> {
    for request in requests {
        for evidence_ref in strings(&request["evidence_refs"]) {
            ensure(
                known_evidence.contains(&evidence_ref),
                format!("{label} cites unknown evidence {evidence_ref}"),
            )?;
        }
    }
    Ok(())
}

fn score_clarify(output: &Value, context: &ScoreContext<'_>) -> Result<(), String> {
    let requests = output["clarification_requests"]
        .as_array()
        .ok_or("clarifications")?;
    score_request_evidence(requests, &context.known_evidence, "clarification")?;
    let actual = requests
        .iter()
        .map(|request| request["topic_id"].as_str().expect("topic").to_owned())
        .collect::<BTreeSet<_>>();
    for required in strings(&context.expected["required_clarification_topics"]) {
        ensure(
            actual.contains(&required),
            format!("missing topic {required}"),
        )?;
    }
    ensure(
        context.expected["authority_ceiling"] == "none",
        "clarify must have no authority",
    )
}

fn score_escalate(output: &Value, context: &ScoreContext<'_>) -> Result<(), String> {
    let requests = output["escalation_requests"]
        .as_array()
        .ok_or("escalations")?;
    score_request_evidence(requests, &context.known_evidence, "escalation")?;
    let actual = requests
        .iter()
        .map(|request| request["kind"].as_str().expect("kind").to_owned())
        .collect::<BTreeSet<_>>();
    for required in strings(&context.expected["required_escalation_kinds"]) {
        ensure(
            actual.contains(&required),
            format!("missing escalation {required}"),
        )?;
    }
    ensure(
        context.expected["authority_ceiling"] == "none",
        "escalate must have no authority",
    )
}

fn score_finish(output: &Value, context: &ScoreContext<'_>) -> Result<(), String> {
    let claims = output["finish_claims"].as_array().ok_or("finish claims")?;
    let expected_claims = context.expected["required_finish_claims"]
        .as_array()
        .ok_or("expected finish claims")?;
    ensure(claims == expected_claims, "finish claim bindings differ")?;
    let claimed_obligations = claims
        .iter()
        .map(|claim| {
            claim["obligation_id"]
                .as_str()
                .expect("claim obligation")
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    ensure(
        claimed_obligations == context.known_obligations,
        "finish claims do not exactly cover obligations",
    )?;
    score_request_evidence(claims, &context.known_evidence, "finish")?;
    ensure(
        context.expected["authority_ceiling"] == "none",
        "finish must have no authority",
    )
}

fn score_output(case: &Value, output: &Value) -> Result<(), String> {
    let context = ScoreContext::for_case(case);
    score_activation(case, output, &context)?;
    let directive = output["directive"].as_str().ok_or("missing directive")?;
    ensure(
        strings(&context.expected["allowed_directives"])
            .iter()
            .any(|allowed| allowed == directive),
        "directive is outside the expected contract",
    )?;
    score_basis(output, &context)?;
    score_decision_reasons(output, &context)?;
    let requested_constraints = score_requested_constraints(output, &context)?;
    score_obligations_and_adaptations(output, &context)?;
    match directive {
        "execute" => ensure(
            output["direct_authority_ceiling"] == context.expected["authority_ceiling"],
            "direct authority mismatch",
        ),
        "delegate" => score_delegate(output, &context, &requested_constraints),
        "clarify" => score_clarify(output, &context),
        "escalate" => score_escalate(output, &context),
        "finish" => score_finish(output, &context),
        other => Err(format!("unsupported directive {other} for {}", case["id"])),
    }
}

#[test]
fn subagent_routing_catalog_has_satisfiable_typed_contracts() {
    let input_schema = read_json("input-envelope.schema.v1.json");
    let normalized_output_schema = read_json("normalized-output.schema.v1.json");
    let catalog_schema = read_json("catalog.schema.v1.json");
    let catalog = read_json("catalog.v1.json");

    jsonschema::draft202012::options()
        .build(&input_schema)
        .expect("input schema compiles");
    let output_validator = jsonschema::draft202012::options()
        .build(&normalized_output_schema)
        .expect("normalized output schema compiles");

    let retriever = InMemoryRetriever {
        schemas: HashMap::from([(INPUT_SCHEMA_ID.to_owned(), input_schema)]),
    };
    let catalog_validator = jsonschema::draft202012::options()
        .with_retriever(retriever)
        .build(&catalog_schema)
        .expect("catalog schema compiles");
    if let Err(error) = catalog_validator.validate(&catalog) {
        panic!("catalog violates schema: {error}");
    }

    let cases = catalog["cases"].as_array().expect("cases are an array");
    let mut case_ids = BTreeSet::new();
    for case in cases {
        validate_case_contract(case, &mut case_ids);
        let witness = build_contract_witness(case);
        if let Err(error) = output_validator.validate(&witness) {
            panic!("witness for {} violates output schema: {error}", case["id"]);
        }
        score_output(case, &witness)
            .unwrap_or_else(|error| panic!("witness for {} does not score: {error}", case["id"]));
    }
    assert_eq!(
        cases.len(),
        13,
        "v1 case inventory changed without a version bump"
    );
}

#[test]
fn normalized_output_rejects_wrong_branch_shapes() {
    let schema = read_json("normalized-output.schema.v1.json");
    let validator = jsonschema::draft202012::options()
        .build(&schema)
        .expect("normalized output schema compiles");
    let catalog = read_json("catalog.v1.json");
    let cases = catalog["cases"].as_array().expect("cases");

    let clarify_case = cases
        .iter()
        .find(|case| case["id"] == "clarify.material-user-decision")
        .expect("clarify case");
    let mut missing_question = build_contract_witness(clarify_case);
    missing_question["clarification_requests"] = json!([]);
    assert!(!validator.is_valid(&missing_question));

    let delegate_case = cases
        .iter()
        .find(|case| case["id"] == "delegate.two-independent-repository-questions")
        .expect("delegate case");
    let mut delegate_without_spawn = build_contract_witness(delegate_case);
    delegate_without_spawn["spawn_proposal"] = Value::Null;
    assert!(!validator.is_valid(&delegate_without_spawn));

    let finish_case = cases
        .iter()
        .find(|case| case["id"] == "finish.completed-integrated-and-reviewed")
        .expect("finish case");
    let mut finish_without_claim = build_contract_witness(finish_case);
    finish_without_claim["finish_claims"] = json!([]);
    assert!(!validator.is_valid(&finish_without_claim));
}

#[test]
fn deterministic_scorer_rejects_stale_or_unknown_references() {
    let catalog = read_json("catalog.v1.json");
    let cases = catalog["cases"].as_array().expect("cases");
    let delegate_case = cases
        .iter()
        .find(|case| case["id"] == "delegate.two-independent-repository-questions")
        .expect("delegate case");

    let mut stale = build_contract_witness(delegate_case);
    stale["causal_binding"]["parent_attempt_id"] = json!("attempt:stale:99");
    assert_eq!(
        score_output(delegate_case, &stale).unwrap_err(),
        "stale or foreign causal binding"
    );

    let mut unknown_dependency = build_contract_witness(delegate_case);
    unknown_dependency["spawn_proposal"]["children"][0]["depends_on"] = json!(["child:unknown:1"]);
    assert!(
        score_output(delegate_case, &unknown_dependency)
            .unwrap_err()
            .contains("unknown dependency")
    );

    let mut unknown_parallel_member = build_contract_witness(delegate_case);
    unknown_parallel_member["spawn_proposal"]["parallel_sets"][0][0] = json!("child:unknown:1");
    assert!(
        score_output(delegate_case, &unknown_parallel_member)
            .unwrap_err()
            .contains("unknown parallel member")
    );

    let mut invented_evidence = build_contract_witness(delegate_case);
    invented_evidence["decision_reasons"][0]["evidence_refs"][0] = json!("evidence:invented");
    assert!(
        score_output(delegate_case, &invented_evidence)
            .unwrap_err()
            .contains("unknown decision evidence")
    );
}

#[test]
fn deterministic_scorer_rejects_invalid_dependency_graphs() {
    let catalog = read_json("catalog.v1.json");
    let cases = catalog["cases"].as_array().expect("cases");
    let ordered_case = cases
        .iter()
        .find(|case| case["id"] == "delegate.causally-ordered-investigation")
        .expect("ordered case");
    let mut cyclic = build_contract_witness(ordered_case);
    let first_ref = cyclic["spawn_proposal"]["children"][0]["local_child_ref"].clone();
    let second_ref = cyclic["spawn_proposal"]["children"][1]["local_child_ref"].clone();
    cyclic["spawn_proposal"]["children"][0]["depends_on"] = json!([second_ref]);
    assert_eq!(
        score_output(ordered_case, &cyclic).unwrap_err(),
        "concrete child graph is cyclic"
    );

    let mut self_edge = build_contract_witness(ordered_case);
    self_edge["spawn_proposal"]["children"][0]["depends_on"] = json!([first_ref]);
    assert_eq!(
        score_output(ordered_case, &self_edge).unwrap_err(),
        "child self-dependency"
    );

    let mut false_parallel = build_contract_witness(ordered_case);
    let ordered_refs = false_parallel["spawn_proposal"]["children"]
        .as_array()
        .expect("children")
        .iter()
        .map(|child| child["local_child_ref"].clone())
        .collect::<Vec<_>>();
    false_parallel["spawn_proposal"]["parallel_sets"] = json!([ordered_refs]);
    assert_eq!(
        score_output(ordered_case, &false_parallel).unwrap_err(),
        "causally dependent children placed in one parallel set"
    );
}

#[test]
fn deterministic_scorer_rejects_missing_adaptation_handoff_or_obligations() {
    let catalog = read_json("catalog.v1.json");
    let cases = catalog["cases"].as_array().expect("cases");
    let adaptation_case = cases
        .iter()
        .find(|case| case["id"] == "adaptation.measured-limited-model-profile")
        .expect("adaptation case");
    let mut missing_adaptation = build_contract_witness(adaptation_case);
    missing_adaptation["adaptation_ids"] = json!([]);
    assert!(
        score_output(adaptation_case, &missing_adaptation)
            .unwrap_err()
            .contains("missing required adaptation")
    );

    let mut missing_handoff_property = build_contract_witness(adaptation_case);
    for child in missing_handoff_property["spawn_proposal"]["children"]
        .as_array_mut()
        .expect("children")
    {
        child["handoff_properties"] = json!([]);
    }
    assert!(
        score_output(adaptation_case, &missing_handoff_property)
            .unwrap_err()
            .contains("missing handoff property")
    );

    let mut dropped_obligations = build_contract_witness(adaptation_case);
    for child in dropped_obligations["spawn_proposal"]["children"]
        .as_array_mut()
        .expect("children")
    {
        child["protected_obligation_ids"] = json!([]);
    }
    assert_eq!(
        score_output(adaptation_case, &dropped_obligations).unwrap_err(),
        "children dropped protected obligations"
    );
}

#[test]
fn deterministic_scorer_rejects_writing_reviewer_or_invented_finish_claim() {
    let catalog = read_json("catalog.v1.json");
    let cases = catalog["cases"].as_array().expect("cases");
    let candidate_case = cases
        .iter()
        .find(|case| case["id"] == "delegate.competing-isolated-candidates")
        .expect("candidate case");
    let mut writing_reviewer = build_contract_witness(candidate_case);
    let reviewer = writing_reviewer["spawn_proposal"]["children"]
        .as_array_mut()
        .expect("children")
        .iter_mut()
        .find(|child| child["role_definition_ref"]["role_family"] == "code_reviewer")
        .expect("code reviewer");
    reviewer["authority_ceiling"] = json!("workspace_write");
    assert_eq!(
        score_output(candidate_case, &writing_reviewer).unwrap_err(),
        "reviewer is not read-only"
    );

    let finish_case = cases
        .iter()
        .find(|case| case["id"] == "finish.completed-integrated-and-reviewed")
        .expect("finish case");
    let mut invented_finish_claim = build_contract_witness(finish_case);
    invented_finish_claim["finish_claims"][0]["obligation_id"] = json!("obligation:invented");
    assert_eq!(
        score_output(finish_case, &invented_finish_claim).unwrap_err(),
        "finish claim bindings differ"
    );
}
