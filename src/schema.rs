//! SPDX-License-Identifier: GPL-3.0-or-later
//! Historical v1 reader support and current v2 document validation.
//!
//! [`check_version`] accepts historical v1.x documents; its schema is
//! `schemas/observed-crypto-v1.json`. Live report/check producers emit
//! `observed-crypto-v2.4` through `observed-crypto-v2.9`
//! (`src/evidence.rs` is the emitter of record: v2.5 when the window
//! certified execution attribution, v2.6 when a sysctl context was
//! sampled, v2.7 when the capture retired an owned corpse, v2.8 when
//! the window projected request/fetch/load/query evidence, v2.9 when
//! the window sealed a 6D trace fold);
//! [`check_version_v2`], [`validate_v2`] and [`check_v2_semantics`]
//! own that contract. Minor additions are optional; field readers
//! ignore unknown keys while validators stay strict.
//!
//! Phase 1 adds `observed-crypto-v2.8` (request/fetch/load/query
//! evidence); Phase 2 adds `observed-crypto-v2.9` (6D trace
//! projection); the emitter of record stays `src/evidence.rs`.

/// True iff a v1.x reader accepts this `schema_version`: accepts
/// `observed-crypto-v1` (implicit .0) and `observed-crypto-v1.<minor>`;
/// rejects other majors and anything unparseable.
pub fn check_version(v: &str) -> bool {
    let Some(rest) = v.strip_prefix("observed-crypto-v") else {
        return false;
    };
    let (major, minor) = match rest.split_once('.') {
        Some((maj, min)) => (maj, Some(min)),
        None => (rest, None),
    };
    if major != "1" {
        return false;
    }
    match minor {
        None => true,
        Some(m) => !m.is_empty() && m.bytes().all(|b| b.is_ascii_digit()),
    }
}

// ---------------------------------------------------------------- v2 schema
//
// `observed-crypto-v2` reader contract (continuation R08). Unlike the
// v1 required-key walker, v2 validation is actual JSON Schema
// validation: [`validate_v2`] interprets `schemas/observed-crypto-v2.json`
// (types, enums, required fields, ranges, `additionalProperties`,
// `$ref`) against the document, and [`check_v2_semantics`] enforces
// the cross-field rules plain JSON Schema cannot express (object
// reference integrity, window consistency, record invariants,
// privacy shape).

/// Embedded v2 schema source (compile-time: always in sync with the
/// tree; external consumers use the schema file directly).
pub const V2_SCHEMA_JSON: &str = include_str!("../schemas/observed-crypto-v2.json");

/// True iff a v2.x reader accepts this `schema_version`: accepts
/// `observed-crypto-v2` (implicit .0) and `observed-crypto-v2.<minor>`;
/// rejects other majors and anything unparseable. Minor versions add
/// OPTIONAL keys only — readers must ignore unknown keys. The minor
/// domain is REPRESENTABLE u64 (P2fix10 NEW-62 — one minor domain
/// across raw intake + both presenter shapes + persistence: a digit
/// string above `u64::MAX` rejects like any unsupported version,
/// never erases to sectionless downstream).
pub fn check_version_v2(v: &str) -> bool {
    let Some(rest) = v.strip_prefix("observed-crypto-v") else {
        return false;
    };
    let (major, minor) = match rest.split_once('.') {
        Some((maj, min)) => (maj, Some(min)),
        None => (rest, None),
    };
    if major != "2" {
        return false;
    }
    match minor {
        None => true,
        Some(m) => {
            !m.is_empty() && m.bytes().all(|b| b.is_ascii_digit()) && m.parse::<u64>().is_ok()
        }
    }
}

/// One JSON Schema validation failure: the JSON path of the
/// offending value plus a one-line reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaError {
    pub path: String,
    pub message: String,
}

impl std::fmt::Display for SchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

impl std::error::Error for SchemaError {}

/// Keys that must never appear in a v2 document (R07): raw argv,
/// cmdline, environment and runtime addresses have no legitimate
/// carrier. The schema's `additionalProperties: false` rejects them
/// structurally; [`check_v2_semantics`] rejects them by name as a
/// second layer (and as the explicit failure when a future schema
/// edit loosens a structural block).
pub const FORBIDDEN_V2_KEYS: &[&str] = &[
    "argv",
    "cmdline",
    "cmd_line",
    "address",
    "addresses",
    "runtime_address",
    "raw_address",
    "env",
    "environ",
    "environment_variables",
];

/// Validate a document against `schemas/observed-crypto-v2.json`
/// (full types/enums/required fields/ranges, no silent keyword
/// skips: schemas using unsupported keywords fail closed).
pub fn validate_v2(doc: &serde_json::Value) -> Result<(), SchemaError> {
    validate_v2_with_schema(V2_SCHEMA_JSON, doc)
}

/// Validate a document against an explicit v2 schema text with
/// the same embedded engine (compat aid: pinning what an older
/// strict minor reader accepts, or what a newer candidate schema
/// would accept). Unparseable schema text fails closed.
pub fn validate_v2_with_schema(
    schema_json: &str,
    doc: &serde_json::Value,
) -> Result<(), SchemaError> {
    let schema: serde_json::Value = serde_json::from_str(schema_json).map_err(|e| SchemaError {
        path: "$".to_string(),
        message: format!("v2 schema text is not valid JSON: {e}"),
    })?;
    validate_against(&schema, doc, &schema, "$", 0)
}

/// Guard against `$ref` cycles (a schema that references itself
/// never terminates validation, so depth fails closed).
const MAX_REF_DEPTH: u32 = 64;

fn schema_err(path: &str, message: String) -> SchemaError {
    SchemaError {
        path: path.to_string(),
        message,
    }
}

/// Reject any schema object carrying a keyword the validator does
/// not implement: a schema we cannot fully interpret must never
/// silently pass.
fn check_keywords(
    schema: &serde_json::Map<String, serde_json::Value>,
    path: &str,
) -> Result<(), SchemaError> {
    const SUPPORTED: &[&str] = &[
        "$schema",
        "$id",
        "title",
        "description",
        "$defs",
        "$ref",
        "type",
        "enum",
        "const",
        "required",
        "properties",
        "additionalProperties",
        "items",
        "minimum",
        "maximum",
        "minLength",
        "maxLength",
        "pattern",
        "minItems",
        "maxItems",
        "anyOf",
        "allOf",
        "oneOf",
    ];
    for key in schema.keys() {
        if !SUPPORTED.contains(&key.as_str()) {
            return Err(schema_err(
                path,
                format!("unsupported schema keyword {key:?} (fail closed)"),
            ));
        }
    }
    Ok(())
}

fn json_type(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Object(_) => "object",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Number(_) => {
            if is_integer_value(v) {
                "integer"
            } else {
                "number"
            }
        }
    }
}

/// JSON Schema `integer`: u64/i64, or a finite float with zero
/// fractional part (so `1.0` is an integer; `1.5` and huge
/// out-of-range floats are not silently truncated).
fn is_integer_value(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Number(n) => {
            n.as_u64().is_some()
                || n.as_i64().is_some()
                || n.as_f64()
                    .is_some_and(|f| f.is_finite() && f.fract() == 0.0)
        }
        _ => false,
    }
}

fn check_type(
    t: &serde_json::Value,
    doc: &serde_json::Value,
    path: &str,
) -> Result<(), SchemaError> {
    let names: Vec<&str> = match t {
        serde_json::Value::String(s) => vec![s.as_str()],
        serde_json::Value::Array(items) => items
            .iter()
            .map(|v| {
                v.as_str()
                    .ok_or_else(|| schema_err(path, "type array holds a non-string".to_string()))
            })
            .collect::<Result<_, _>>()?,
        _ => {
            return Err(schema_err(
                path,
                "type must be a string or an array of strings".to_string(),
            ));
        }
    };
    for name in &names {
        let hit = match *name {
            "null" => doc.is_null(),
            "boolean" => doc.is_boolean(),
            "object" => doc.is_object(),
            "array" => doc.is_array(),
            "string" => doc.is_string(),
            "integer" => is_integer_value(doc),
            "number" => doc.is_number(),
            other => {
                return Err(schema_err(path, format!("unknown type {other:?}")));
            }
        };
        if hit {
            return Ok(());
        }
    }
    Err(schema_err(
        path,
        format!("expected {}, found {}", names.join("/"), json_type(doc)),
    ))
}

/// Exact integer view of a JSON number: u64/i64 directly, integral
/// floats within i128 range by cast (range-checked first, since
/// `as` saturates). Fractional or gigantic floats yield `None`.
fn number_as_i128(n: &serde_json::Number) -> Option<i128> {
    if let Some(u) = n.as_u64() {
        return Some(u as i128);
    }
    if let Some(i) = n.as_i64() {
        return Some(i as i128);
    }
    let f = n.as_f64()?;
    if !f.is_finite() || f.fract() != 0.0 {
        return None;
    }
    const LO: f64 = -170141183460469231731687303715884105728.0; // i128::MIN
    const HI: f64 = 170141183460469231731687303715884105728.0; // 2^127
    if !(LO..HI).contains(&f) {
        return None;
    }
    Some(f as i128)
}

/// Exact number ordering: i128 when both sides are integral (so
/// 2^64-as-float still exceeds u64::MAX, which rounds to 2^64 as an
/// f64), float total order otherwise.
fn cmp_numbers(a: &serde_json::Number, b: &serde_json::Number) -> std::cmp::Ordering {
    match (number_as_i128(a), number_as_i128(b)) {
        (Some(x), Some(y)) => x.cmp(&y),
        _ => a
            .as_f64()
            .unwrap_or(0.0)
            .total_cmp(&b.as_f64().unwrap_or(0.0)),
    }
}

fn bound_number<'a>(
    schema: &'a serde_json::Value,
    keyword: &str,
    path: &str,
) -> Result<&'a serde_json::Number, SchemaError> {
    match schema {
        serde_json::Value::Number(n) => Ok(n),
        _ => Err(schema_err(
            path,
            format!("{keyword} bound must be a number"),
        )),
    }
}

fn bound_count(schema: &serde_json::Value, keyword: &str, path: &str) -> Result<u64, SchemaError> {
    match schema {
        serde_json::Value::Number(n) if n.as_u64().is_some() => Ok(n.as_u64().unwrap()),
        _ => Err(schema_err(
            path,
            format!("{keyword} must be a non-negative integer"),
        )),
    }
}

/// Resolve a local `$ref` (`#` or `#/a/b/c` with `~0`/`~1`
/// escapes) against the schema root. Remote refs are unsupported
/// and fail closed.
fn resolve_ref<'a>(
    target: &str,
    root: &'a serde_json::Value,
    path: &str,
) -> Result<&'a serde_json::Value, SchemaError> {
    let pointer = target.strip_prefix('#').ok_or_else(|| {
        schema_err(
            path,
            format!("only local $ref is supported, found {target:?}"),
        )
    })?;
    if pointer.is_empty() {
        return Ok(root);
    }
    if !pointer.starts_with('/') {
        return Err(schema_err(path, format!("malformed $ref {target:?}")));
    }
    let mut current = root;
    for raw in pointer[1..].split('/') {
        let key = raw.replace("~1", "/").replace("~0", "~");
        current = match current {
            serde_json::Value::Object(map) => map
                .get(&key)
                .ok_or_else(|| schema_err(path, format!("$ref {target:?} resolves nowhere")))?,
            serde_json::Value::Array(items) => {
                let index: usize = key
                    .parse()
                    .map_err(|_| schema_err(path, format!("$ref {target:?} resolves nowhere")))?;
                items
                    .get(index)
                    .ok_or_else(|| schema_err(path, format!("$ref {target:?} resolves nowhere")))?
            }
            _ => {
                return Err(schema_err(
                    path,
                    format!("$ref {target:?} resolves nowhere"),
                ));
            }
        };
    }
    Ok(current)
}

/// Apply a bool-or-schema node (`additionalProperties`, `items`).
fn apply_node(
    node: &serde_json::Value,
    doc: &serde_json::Value,
    root: &serde_json::Value,
    path: &str,
    depth: u32,
) -> Result<(), SchemaError> {
    if let Some(allowed) = node.as_bool() {
        if allowed {
            return Ok(());
        }
        return Err(schema_err(path, "value forbidden here".to_string()));
    }
    validate_against(node, doc, root, path, depth)
}

fn validate_against(
    schema: &serde_json::Value,
    doc: &serde_json::Value,
    root: &serde_json::Value,
    path: &str,
    depth: u32,
) -> Result<(), SchemaError> {
    if depth > MAX_REF_DEPTH {
        return Err(schema_err(path, "$ref depth exceeded (cycle?)".to_string()));
    }
    if let Some(allowed) = schema.as_bool() {
        if allowed {
            return Ok(());
        }
        return Err(schema_err(
            path,
            "value forbidden by `false` schema".to_string(),
        ));
    }
    let obj = schema
        .as_object()
        .ok_or_else(|| schema_err(path, "schema node must be an object or boolean".to_string()))?;
    check_keywords(obj, path)?;
    // `$ref` plus draft 2020-12 sibling semantics: the target and
    // every sibling keyword apply.
    if let Some(target) = obj.get("$ref") {
        let name = target
            .as_str()
            .ok_or_else(|| schema_err(path, "$ref target must be a string".to_string()))?;
        let resolved = resolve_ref(name, root, path)?;
        validate_against(resolved, doc, root, path, depth + 1)?;
    }
    if let Some(t) = obj.get("type") {
        check_type(t, doc, path)?;
    }
    if let Some(variants) = obj.get("enum") {
        let list = variants
            .as_array()
            .ok_or_else(|| schema_err(path, "enum must be an array".to_string()))?;
        if !list.iter().any(|v| v == doc) {
            return Err(schema_err(path, "value is not one of enum".to_string()));
        }
    }
    if let Some(want) = obj.get("const") {
        if want != doc {
            return Err(schema_err(path, "value does not equal const".to_string()));
        }
    }
    // Object keywords apply to objects only (ignored otherwise, per
    // the specification); enforcement comes from combining them
    // with `type: object`.
    if let Some(map) = doc.as_object() {
        if let Some(req) = obj.get("required") {
            let keys = req
                .as_array()
                .ok_or_else(|| schema_err(path, "required must be an array".to_string()))?;
            for key in keys {
                let name = key
                    .as_str()
                    .ok_or_else(|| schema_err(path, "required holds a non-string".to_string()))?;
                if !map.contains_key(name) {
                    return Err(schema_err(path, format!("missing required key {name:?}")));
                }
            }
        }
        if let Some(props) = obj.get("properties") {
            let subs = props
                .as_object()
                .ok_or_else(|| schema_err(path, "properties must be an object".to_string()))?;
            for (key, sub) in subs {
                if let Some(value) = map.get(key) {
                    validate_against(sub, value, root, &format!("{path}.{key}"), depth)?;
                }
            }
        }
        if let Some(extra) = obj.get("additionalProperties") {
            let declared: std::collections::BTreeSet<&str> = obj
                .get("properties")
                .and_then(|v| v.as_object())
                .map(|m| m.keys().map(String::as_str).collect())
                .unwrap_or_default();
            for (key, value) in map {
                if !declared.contains(key.as_str()) {
                    apply_node(extra, value, root, &format!("{path}.{key}"), depth)?;
                }
            }
        }
    }
    if let Some(items) = doc.as_array() {
        if let Some(node) = obj.get("items") {
            for (index, value) in items.iter().enumerate() {
                apply_node(node, value, root, &format!("{path}[{index}]"), depth)?;
            }
        }
        if let Some(limit) = obj.get("minItems") {
            let min = bound_count(limit, "minItems", path)?;
            if (items.len() as u64) < min {
                return Err(schema_err(
                    path,
                    format!("array has {} items, minItems {min}", items.len()),
                ));
            }
        }
        if let Some(limit) = obj.get("maxItems") {
            let max = bound_count(limit, "maxItems", path)?;
            if (items.len() as u64) > max {
                return Err(schema_err(
                    path,
                    format!("array has {} items, maxItems {max}", items.len()),
                ));
            }
        }
    }
    if let Some(text) = doc.as_str() {
        if let Some(limit) = obj.get("minLength") {
            let min = bound_count(limit, "minLength", path)?;
            if (text.chars().count() as u64) < min {
                return Err(schema_err(
                    path,
                    format!("string is shorter than minLength {min}"),
                ));
            }
        }
        if let Some(limit) = obj.get("maxLength") {
            let max = bound_count(limit, "maxLength", path)?;
            if (text.chars().count() as u64) > max {
                return Err(schema_err(
                    path,
                    format!("string is longer than maxLength {max}"),
                ));
            }
        }
        if let Some(pat) = obj.get("pattern") {
            let pat = pat
                .as_str()
                .ok_or_else(|| schema_err(path, "pattern must be a string".to_string()))?;
            // `pattern` (P2fix6 NEW-37): the validator ships no
            // regex engine — the single shipped pattern (the
            // canonical lowercase 16-hex exemplar spelling)
            // evaluates by its exact manual equivalent; any other
            // pattern fails closed (a schema the validator cannot
            // evaluate proves nothing). Never echoes the input.
            if pat != "^[0-9a-f]{16}$" {
                return Err(schema_err(
                    path,
                    "unsupported pattern (fail closed)".to_string(),
                ));
            }
            if text.len() != 16
                || !text
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err(schema_err(
                    path,
                    "string does not match pattern".to_string(),
                ));
            }
        }
    }
    if let serde_json::Value::Number(number) = doc {
        if let Some(limit) = obj.get("minimum") {
            let bound = bound_number(limit, "minimum", path)?;
            if cmp_numbers(number, bound) == std::cmp::Ordering::Less {
                return Err(schema_err(path, "number is below minimum".to_string()));
            }
        }
        if let Some(limit) = obj.get("maximum") {
            let bound = bound_number(limit, "maximum", path)?;
            if cmp_numbers(number, bound) == std::cmp::Ordering::Greater {
                return Err(schema_err(path, "number is above maximum".to_string()));
            }
        }
    }
    if let Some(list) = obj.get("anyOf") {
        let variants = list
            .as_array()
            .ok_or_else(|| schema_err(path, "anyOf must be an array".to_string()))?;
        if variants.is_empty() {
            return Err(schema_err(path, "anyOf must not be empty".to_string()));
        }
        let mut failures = Vec::new();
        let mut matched = false;
        for variant in variants {
            match validate_against(variant, doc, root, path, depth) {
                Ok(()) => {
                    matched = true;
                    break;
                }
                Err(e) => failures.push(e.message),
            }
        }
        if !matched {
            return Err(schema_err(
                path,
                format!("no anyOf branch matched ({})", failures.join("; ")),
            ));
        }
    }
    if let Some(list) = obj.get("allOf") {
        let variants = list
            .as_array()
            .ok_or_else(|| schema_err(path, "allOf must be an array".to_string()))?;
        for variant in variants {
            validate_against(variant, doc, root, path, depth)?;
        }
    }
    if let Some(list) = obj.get("oneOf") {
        let variants = list
            .as_array()
            .ok_or_else(|| schema_err(path, "oneOf must be an array".to_string()))?;
        let hits = variants
            .iter()
            .filter(|v| validate_against(v, doc, root, path, depth).is_ok())
            .count();
        if hits != 1 {
            return Err(schema_err(
                path,
                format!("oneOf matched {hits} branches, want exactly 1"),
            ));
        }
    }
    Ok(())
}

/// Cross-field v2 rules plain JSON Schema cannot express: the
/// version gate, forbidden argv/cmdline/address keys, window
/// consistency, object reference integrity (full
/// fingerprint/device/inode triples), record invariants, site
/// timestamp order with effective-window containment (current and
/// fenced) and key uniqueness, status/reasons agreement with
/// COMPLETE reconciled against window gaps, coverage, loss, and
/// unattributed calls, policy verdict combination with
/// definite-within-possible bounds and per-site evidence totals,
/// and fenced-bucket generation agreement. Fails closed on
/// malformed shape (this runs after [`validate_v2`] in the normal
/// pipeline, but never assumes it did).
pub fn check_v2_semantics(doc: &serde_json::Value) -> Result<(), String> {
    let root = doc
        .as_object()
        .ok_or_else(|| "doc: expected object".to_string())?;
    let version = root
        .get("schema_version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "doc.schema_version: expected string".to_string())?;
    if !check_version_v2(version) {
        return Err(format!("doc.schema_version: rejected {version:?}"));
    }
    sweep_forbidden_keys(doc, "$")?;
    let bounds = check_window(root)?;
    check_object_refs(root)?;
    check_records(root, bounds)?;
    check_legacy_partition(root)?;
    check_execution_attributions(root, bounds)?;
    check_traversal_fingerprints(root)?;
    check_package_provenance(root)?;
    check_preview_count_provenance(root)?;
    check_dynamic_sections(root)?;
    check_v26_sections(root)?;
    check_request_evidence(root)?;
    check_trace_summary(root)?;
    Ok(())
}

/// NEW-33 fix9: duplicate-preserving JSON mirror — objects keep
/// every member in wire order (`serde_json::Value` last-wins
/// duplicates away, so the `Value` gate cannot see them). Only the
/// object-member lists are consumed (duplicate detection); scalars
/// exist so any document parses.
enum RawJson {
    Null,
    Bool,
    Number,
    String(String),
    Array(Vec<RawJson>),
    Object(Vec<(String, RawJson)>),
}

impl<'de> serde::Deserialize<'de> for RawJson {
    fn deserialize<D: serde::Deserializer<'de>>(read: D) -> Result<Self, D::Error> {
        struct RawVisitor;
        impl<'de> serde::de::Visitor<'de> for RawVisitor {
            type Value = RawJson;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("any JSON value")
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<RawJson, E> {
                Ok(RawJson::Null)
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<RawJson, E> {
                Ok(RawJson::Null)
            }
            fn visit_bool<E: serde::de::Error>(self, _v: bool) -> Result<RawJson, E> {
                Ok(RawJson::Bool)
            }
            fn visit_i64<E: serde::de::Error>(self, _v: i64) -> Result<RawJson, E> {
                Ok(RawJson::Number)
            }
            fn visit_u64<E: serde::de::Error>(self, _v: u64) -> Result<RawJson, E> {
                Ok(RawJson::Number)
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<RawJson, E> {
                if v.is_finite() {
                    Ok(RawJson::Number)
                } else {
                    Err(E::custom("doc: non-finite number"))
                }
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<RawJson, E> {
                Ok(RawJson::String(v.to_owned()))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<RawJson, E> {
                Ok(RawJson::String(v))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<RawJson, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element()? {
                    items.push(item);
                }
                Ok(RawJson::Array(items))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<RawJson, A::Error> {
                // Collect, never dedup: duplicate members stay visible.
                let mut members = Vec::new();
                while let Some((key, value)) = map.next_entry::<String, RawJson>()? {
                    members.push((key, value));
                }
                Ok(RawJson::Object(members))
            }
        }
        read.deserialize_any(RawVisitor)
    }
}

/// Raw duplicate-key walk shared by every raw check (P2fix4
/// NEW-8 — request_evidence, trace_summary, envelope, OTLP
/// response): object keys repeat nowhere in the walked tree.
/// Diagnostics name FIXED caller roots + STRUCTURAL positions
/// only (P2fix5 NEW-25 — object members by member index, array
/// items by item index; raw input keys NEVER echo — neither the
/// duplicate key nor any ancestor key); `root` labels the
/// diagnostic path root.
fn walk_raw_duplicates(value: &RawJson, path: &mut Vec<String>, root: &str) -> Result<(), String> {
    match value {
        RawJson::Object(members) => {
            let mut seen = std::collections::BTreeSet::new();
            for (key, _) in members {
                if !seen.insert(key.clone()) {
                    return Err(format!("{root}.{}: duplicate field", path.join(".")));
                }
            }
            for (index, (_, member)) in members.iter().enumerate() {
                path.push(format!("#{index}"));
                walk_raw_duplicates(member, path, root)?;
                path.pop();
            }
            Ok(())
        }
        RawJson::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                path.push(index.to_string());
                walk_raw_duplicates(item, path, root)?;
                path.pop();
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// OTLP/HTTP response duplicate members (P2fix4 NEW-8): reject
/// duplicate object keys anywhere in the RAW response bytes —
/// BEFORE `Value` normalization collapses them (last-wins),
/// which would hide a prior `partialSuccess` (or count) behind
/// a later clean block. Checked before counting acceptance.
pub fn check_otlp_response_raw_duplicates(text: &str) -> Result<(), String> {
    let raw: RawJson =
        serde_json::from_str(text).map_err(|error| format!("otlp: invalid JSON ({error})"))?;
    walk_raw_duplicates(&raw, &mut vec![], "otlp")
}

/// NEW-33 fix9: reject duplicate object keys anywhere under the
/// top-level `request_evidence` section of the RAW document text —
/// BEFORE `Value` normalization collapses them (last-wins). The
/// document gate below receives a `Value`, so without this raw
/// check a duplicated `start_ns`/`end_ns` is invisible to it.
/// NEW-33-OPEN fix10: a REPEATED top-level `request_evidence`
/// member is rejected here too — the scan used to walk only the
/// first member while `Value` parsing last-wins, so a second
/// member replaced the checked one and concealed nested
/// duplicates. Keys outside the section keep their historical
/// last-wins behavior (out of scope for this finding).
pub fn check_request_evidence_raw_duplicates(text: &str) -> Result<(), String> {
    let raw: RawJson =
        serde_json::from_str(text).map_err(|error| format!("doc: invalid JSON ({error})"))?;
    let section = match &raw {
        RawJson::Object(members) => {
            let mut sections = members
                .iter()
                .filter(|(key, _)| key == "request_evidence")
                .map(|(_, value)| value);
            let first = sections.next();
            if sections.next().is_some() {
                return Err("doc.request_evidence: duplicate field `request_evidence` \
                     (a repeated top-level section conceals its members)"
                    .to_string());
            }
            first
        }
        _ => None,
    };
    let Some(section) = section else {
        return Ok(());
    };
    let mut path = vec!["request_evidence".to_string()];
    walk_raw_duplicates(section, &mut path, "doc")
}

/// P2fix1 item 23: reject duplicate object keys anywhere under a
/// `trace_summary` section of the RAW text — BEFORE `Value`
/// normalization collapses them (last-wins). A duplicated by_api
/// key would silently pick one distribution for an API identity;
/// the typed gate below receives a `Value`, so without this raw
/// check the duplication is invisible to it. Both text shapes are
/// covered: top-level `trace_summary` (document text) and
/// `document.trace_summary` (service envelope bytes — the
/// presenter calls this on window bytes before folding). Keys
/// outside the section keep their historical last-wins behavior.
pub fn check_trace_summary_raw_duplicates(text: &str) -> Result<(), String> {
    let raw: RawJson =
        serde_json::from_str(text).map_err(|error| format!("doc: invalid JSON ({error})"))?;
    fn section_members<'a>(raw: &'a RawJson, key: &str) -> Vec<&'a RawJson> {
        match raw {
            RawJson::Object(members) => members
                .iter()
                .filter(|(k, _)| k == key)
                .map(|(_, v)| v)
                .collect(),
            _ => vec![],
        }
    }
    // A repeated section member itself rejects (it would conceal
    // the checked one under last-wins).
    let mut sections: Vec<(&RawJson, Vec<String>)> = vec![];
    let tops = section_members(&raw, "trace_summary");
    if tops.len() > 1 {
        return Err("doc.trace_summary: duplicate field `trace_summary`".to_string());
    }
    for top in tops {
        sections.push((top, vec!["trace_summary".to_string()]));
    }
    for doc in section_members(&raw, "document") {
        let nested = section_members(doc, "trace_summary");
        if nested.len() > 1 {
            return Err("doc.document.trace_summary: duplicate field `trace_summary`".to_string());
        }
        for n in nested {
            sections.push((n, vec!["document".to_string(), "trace_summary".to_string()]));
        }
    }
    for (section, mut path) in sections {
        walk_raw_duplicates(section, &mut path, "doc")?;
    }
    Ok(())
}

/// P2fix7 NEW-42: reject duplicate object keys anywhere under an
/// `api_activity` section of the RAW text — BEFORE `Value`
/// normalization collapses them (last-wins). A duplicated member
/// inside one coverage row (or its nested `gaps`) would silently
/// pick one value for a coverage input; the typed gate below
/// receives a `Value`, so without this raw check the duplication
/// is invisible to it. Both text shapes are covered: top-level
/// `api_activity` (document text) and `document.api_activity`
/// (service envelope bytes — mirroring the trace-section check).
/// Keys outside the section keep their historical last-wins
/// behavior.
pub fn check_api_activity_raw_duplicates(text: &str) -> Result<(), String> {
    let raw: RawJson =
        serde_json::from_str(text).map_err(|error| format!("doc: invalid JSON ({error})"))?;
    fn section_members<'a>(raw: &'a RawJson, key: &str) -> Vec<&'a RawJson> {
        match raw {
            RawJson::Object(members) => members
                .iter()
                .filter(|(k, _)| k == key)
                .map(|(_, v)| v)
                .collect(),
            _ => vec![],
        }
    }
    // A repeated section member itself rejects (it would conceal
    // the checked one under last-wins).
    let mut sections: Vec<(&RawJson, Vec<String>)> = vec![];
    let tops = section_members(&raw, "api_activity");
    if tops.len() > 1 {
        return Err("doc.api_activity: duplicate field `api_activity`".to_string());
    }
    for top in tops {
        sections.push((top, vec!["api_activity".to_string()]));
    }
    for doc in section_members(&raw, "document") {
        let nested = section_members(doc, "api_activity");
        if nested.len() > 1 {
            return Err("doc.document.api_activity: duplicate field `api_activity`".to_string());
        }
        for n in nested {
            sections.push((n, vec!["document".to_string(), "api_activity".to_string()]));
        }
    }
    for (section, mut path) in sections {
        walk_raw_duplicates(section, &mut path, "doc")?;
    }
    Ok(())
}

/// P2fix8 NEW-51: reject duplicate discriminator members
/// (`schema` / `schema_version`) at a document's top level (or
/// its `document.`-nested object) in the RAW text — BEFORE
/// `Value` normalization collapses them (last-wins). A repeated
/// discriminator would let one version conceal the checked one
/// from the trigger; the typed gate below receives a `Value`,
/// so without this raw check the duplication is invisible to
/// it. (Service envelopes + checkpoints are whole-tree strict
/// already via [`check_envelope_raw_duplicates`].)
pub fn check_discriminator_raw_duplicates(text: &str) -> Result<(), String> {
    let raw: RawJson =
        serde_json::from_str(text).map_err(|error| format!("doc: invalid JSON ({error})"))?;
    fn members(raw: &RawJson) -> Vec<&Vec<(String, RawJson)>> {
        match raw {
            RawJson::Object(members) => vec![members],
            _ => vec![],
        }
    }
    fn nested<'a>(raw: &'a RawJson, key: &str) -> Vec<&'a RawJson> {
        match raw {
            RawJson::Object(members) => members
                .iter()
                .filter(|(k, _)| k == key)
                .map(|(_, v)| v)
                .collect(),
            _ => vec![],
        }
    }
    let mut levels: Vec<(&Vec<(String, RawJson)>, &str)> = vec![];
    for top in members(&raw) {
        levels.push((top, "doc"));
    }
    for doc in nested(&raw, "document") {
        for inner in members(doc) {
            levels.push((inner, "doc.document"));
        }
    }
    for (level, where_) in levels {
        for key in ["schema", "schema_version"] {
            let n = level.iter().filter(|(k, _)| k == key).count();
            if n > 1 {
                return Err(format!("{where_}: duplicate field `{key}`"));
            }
        }
    }
    Ok(())
}

/// P2fix2 item 13: reject duplicate object keys ANYWHERE in a
/// service window envelope's RAW bytes — BEFORE `Value`
/// normalization collapses them (last-wins). A repeated envelope
/// `document` (or any nested key) would conceal the unchecked
/// section under last-wins; the fold below receives a `Value`, so
/// without this raw check the duplication is invisible to it.
/// Whole-tree strict (unlike the v2-document historical scope
/// above): service envelopes are machine-written JSON that never
/// legitimately duplicates a key.
pub fn check_envelope_raw_duplicates(text: &str) -> Result<(), String> {
    let raw: RawJson =
        serde_json::from_str(text).map_err(|error| format!("envelope: invalid JSON ({error})"))?;
    walk_raw_duplicates(&raw, &mut vec![], "envelope")
}

/// Top-level raw string members for one key, in wire order
/// (P2fix18 NEW-110 — duplicate-preserving: a last-wins
/// `Value` cannot show a first `schema` hidden behind a
/// second, so settlement-authority classification reads the
/// raw wire instead). Non-string members for `key` are
/// skipped (never claimed); non-object text and invalid JSON
/// report `None` (claim nothing — the strict parser convicts
/// them on its own path).
pub fn raw_top_string_members(text: &str, key: &str) -> Option<Vec<String>> {
    let raw: RawJson = serde_json::from_str(text).ok()?;
    match raw {
        RawJson::Object(members) => Some(
            members
                .into_iter()
                .filter(|(k, _)| k == key)
                .filter_map(|(_, v)| match v {
                    RawJson::String(s) => Some(s),
                    _ => None,
                })
                .collect(),
        ),
        _ => None,
    }
}

/// True iff the raw bytes carry an explicit `"schema":
/// "<schema>"` discriminator ANYWHERE (P2fix19 NEW-119 —
/// the malformed-content fallback for settlement-authority
/// classification): the `"schema"` key, optional JSON
/// whitespace, `:`, optional whitespace, then the exact
/// quoted schema value. Byte-level (no UTF-8 requirement
/// — malformed content may be binary), parse-free (a
/// truncated tail cannot hide a complete discriminator).
/// A complete discriminator followed by malformed content
/// still CLAIMS (fail closed — never silently ignored);
/// only a tear INSIDE the discriminator itself hides the
/// claim (indistinguishable from junk — documented
/// residual).
pub fn raw_contains_schema_claim(bytes: &[u8], schema: &str) -> bool {
    const KEY: &[u8; 8] = b"\"schema\"";
    let val = schema.as_bytes();
    let mut i = 0usize;
    while i + KEY.len() <= bytes.len() {
        let rel = match bytes[i..].windows(KEY.len()).position(|w| w == KEY) {
            Some(p) => p,
            None => return false,
        };
        let mut j = i + rel + KEY.len();
        while j < bytes.len() && matches!(bytes[j], b' ' | b'\t' | b'\n' | b'\r') {
            j += 1;
        }
        if j < bytes.len() && bytes[j] == b':' {
            j += 1;
            while j < bytes.len() && matches!(bytes[j], b' ' | b'\t' | b'\n' | b'\r') {
                j += 1;
            }
            if j + 2 + val.len() <= bytes.len()
                && bytes[j] == b'"'
                && &bytes[j + 1..j + 1 + val.len()] == val
                && bytes[j + 1 + val.len()] == b'"'
            {
                return true;
            }
        }
        i = i + rel + 1;
    }
    false
}

/// NEW-33 fix9: raw-text document intake — the RAW section checks
/// run FIRST (a `Value` has already collapsed duplicates), then
/// the standard structural + semantic pipeline on the parsed
/// document.
pub fn check_v2_document_text(text: &str) -> Result<(), String> {
    check_request_evidence_raw_duplicates(text)?;
    check_trace_summary_raw_duplicates(text)?;
    check_api_activity_raw_duplicates(text)?;
    check_discriminator_raw_duplicates(text)?;
    let doc: serde_json::Value =
        serde_json::from_str(text).map_err(|error| format!("doc: invalid JSON ({error})"))?;
    validate_v2(&doc).map_err(|error| error.to_string())?;
    check_v2_semantics(&doc)
}

/// Request/fetch/load/query evidence (v2.8, Phase 1): the v2.8
/// producer trigger pins BOTH directions at minor 8 exactly (the
/// section is present iff the minor is 8 — nothing else stamps 8;
/// later minors carry it optionally and still validate it when
/// present), and a present section must be coherent — rules plain
/// JSON Schema cannot express. The
/// section-level rules live in one shared place
/// ([`RequestEvidence::validate_strict`], enforced identically by the
/// typed reader): version, surface binding (shape and all — surface
/// 78 is `decoder`, never an `evp` object), canonical row keys and
/// order (duplicate IDs rejected), load coherence, activation
/// coherence, query-partition equality, and the silence-interval
/// rule (a published interval is nonempty, and every zero claim —
/// an observed zero remainder or any covered-but-absent surface —
/// rides one). This gate adds the document-level reconciliations:
/// the silence interval binds inside the document's effective
/// window, the unattributed remainder equals the observed
/// `api_activity` entry sum (an invented remainder is rejected;
/// `Unknown` with positive entries is rejected — positives are
/// preserved, never demoted), and `api_activity` is present
/// whenever the section is. An observed ZERO additionally needs
/// serialized observation evidence behind it (at least one
/// read-receipted activity row — empty or entirely-unreceipted
/// activity proves no observation, so `Observed{0}` over it is
/// rejected).
///
/// Absent sections skip on minors below 8. Unmatched attempt/result
/// edges are legitimate and never forced equal.
fn check_request_evidence(root: &serde_json::Map<String, serde_json::Value>) -> Result<(), String> {
    use crate::provider_observation::request_evidence::{RequestEvidence, Unattributed};
    let version = root
        .get("schema_version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "doc.schema_version: expected string".to_string())?;
    // P2fix10 NEW-62: explicit minor read (no `.parse().ok()`
    // erasure — the version gate above already rejected
    // malformed/overflowing minors, so only the bare
    // implicit-.0 spelling defaults to 0 here).
    let minor: u64 = match version
        .strip_prefix("observed-crypto-v2.")
        .map(|m| m.parse::<u64>())
    {
        Some(Ok(n)) => n,
        _ => 0,
    };
    let Some(section) = root.get("request_evidence") else {
        // NEW-4: the reverse trigger applies to the CURRENT v2.8
        // stamp only — a later minor may be stamped for an
        // unrelated optional feature and validates without this
        // section.
        if minor == 8 {
            return Err(format!(
                "doc.schema_version: minor == 8 needs its request_evidence trigger, got {version:?} without one"
            ));
        }
        return Ok(());
    };
    if minor < 8 {
        return Err(format!(
            "doc.schema_version: request_evidence needs minor >= 8, got {version:?}"
        ));
    }
    // Shared strict typed validation (one read path, not two): the
    // section parses only when every binding/order/coherence rule
    // holds — shapes, duplicates, partitions included.
    let section: RequestEvidence = serde_json::from_value(serde_json::Value::Object(
        section
            .as_object()
            .ok_or_else(|| "doc.request_evidence: expected object".to_string())?
            .clone(),
    ))
    .map_err(|error| format!("doc.request_evidence: strict read rejected it ({error})"))?;
    // GATE-OPEN + NEW-9-OPEN + NEW-16 fix5: every zero claim
    // rides a nonempty silence interval BOUND inside the
    // document's effective window (fail closed). The strict read
    // above already rejects interval-less zeros and empty
    // intervals; the presence refusal below is explicit anyway
    // (the document verdict never relies on a layered check
    // alone), and the binding check convicts unbound intervals.
    if section.claims_zero() && section.silence_window.is_none() {
        return Err(
            "doc.request_evidence: a zero claim needs its published silence interval bound inside the document effective window"
                .to_string(),
        );
    }
    // NEW-9: the published silence interval binds inside the
    // document's effective window — a silence claim outside (or
    // without) the capture window is incoherent (fail closed).
    if let Some(silence) = section.silence_window {
        let window = root.get("window").and_then(|v| v.as_object());
        let effective = |key: &str| window.and_then(|w| w.get(key)).and_then(|v| v.as_u64());
        match (
            effective("effective_start_ns"),
            effective("effective_end_ns"),
        ) {
            (Some(start), Some(end)) if start <= silence.start_ns && silence.end_ns <= end => {}
            _ => {
                return Err(
                    "doc.request_evidence.silence_window: silence interval outside (or without) the document effective window"
                        .to_string(),
                );
            }
        }
    }
    // Document-level remainder reconciliation against the observed
    // operational population (the producer sums the same rows).
    let activity = root
        .get("api_activity")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "doc.api_activity: expected array alongside request_evidence".to_string())?;
    let mut entries = 0u64;
    // GATE-OPEN + GATE fix3 + PINS/NEW-12 fix4: an observed zero
    // needs a serialized successful-read receipt behind it — at
    // least one activity row carrying `gaps.read_receipt`. Empty
    // or entirely-unreceipted activity proves no observation, so
    // `Observed{0}` over it is rejected (a row without an explicit
    // receipt counts unreceipted — fail closed; the `not_attached`
    // bit is ATTACHMENT only and is never counted here).
    // Producer invariant (see `wire::failed_activity`;
    // wording fix7 NEW-28): receipted terminal rows exist only
    // after a successful read of an owner's map — admitted or
    // verified-positive unadmitted (the ROW read receipt, not the
    // admission-gated SCOPE receipt) — failed reads carry no
    // receipt, so they can never receipt a zero.
    let mut receipted_rows = 0u64;
    for (index, row) in activity.iter().enumerate() {
        let row = row
            .as_object()
            .ok_or_else(|| format!("doc.api_activity[{index}]: expected object"))?;
        let row_entries = row
            .get("entries")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| format!("doc.api_activity[{index}].entries: expected u64"))?;
        entries = entries
            .checked_add(row_entries)
            .ok_or_else(|| format!("doc.api_activity[{index}].entries: entry sum overflowed"))?;
        let receipted = row
            .get("gaps")
            .and_then(|g| g.as_object())
            .and_then(|g| g.get("read_receipt"))
            .and_then(|v| v.as_bool())
            .is_some_and(|read_receipt| read_receipt);
        if receipted {
            receipted_rows = receipted_rows.saturating_add(1);
        }
    }
    match &section.unattributed {
        Unattributed::Observed { ops } => {
            if *ops != entries {
                return Err(format!(
                    "doc.request_evidence.unattributed: observed remainder {ops} != api_activity entry sum {entries}"
                ));
            }
            if *ops == 0 && receipted_rows == 0 {
                return Err(
                    "doc.request_evidence.unattributed: observed zero with no read-receipted api_activity row (empty or entirely-unreceipted activity proves no observation)"
                        .to_string(),
                );
            }
        }
        Unattributed::Unknown => {
            if entries != 0 {
                return Err(format!(
                    "doc.request_evidence.unattributed: unknown remainder with {entries} observed entries (positives never demote)"
                ));
            }
        }
    }
    Ok(())
}

/// v2.9 semantic gate (Phase 2): ONE document-level contract
/// (P2fix3 GATE29 — shared with both presenter inputs + restored
/// checkpoints): the producer trigger pins BOTH directions at
/// minor 9 exactly (present iff minor == 9 — nothing else stamps
/// 9; later minors carry it optionally and still validate it when
/// present), and a present section must be coherent (strict typed
/// read + [`TraceSummary::validate`] + coverage-vs-api_activity
/// reconciliation).
fn check_trace_summary(root: &serde_json::Map<String, serde_json::Value>) -> Result<(), String> {
    use crate::provider_observation::trace as t;
    let doc = serde_json::Value::Object(root.clone());
    let parsed = root
        .get("trace_summary")
        .map(t::parse_trace_section)
        .transpose()
        .map_err(|error| format!("doc.trace_summary: {error}"))?;
    // Raw shape: canonical `schema_version` (P2fix8 NEW-51 — a
    // foreign `schema` alias rejects, never overrides).
    let minor = t::canonical_minor(&doc, t::DocShape::Raw)
        .map_err(|error| format!("doc.trace_summary: {error}"))?;
    t::check_trace_contract(minor, parsed.as_ref(), root.get("api_activity"))
        .map_err(|error| format!("doc.trace_summary: {error}"))?;
    Ok(())
}

/// Coarse OpenSSL families the v2.6 producer may emit (T5 schema
/// D-record rule 1): major.minor only, never patch strings.
pub const COARSE_OPENSSL_FAMILIES: &[&str] = &["3.0", "3.5", "3.6", "4.0"];

/// Sampled sysctl context + coarse version domain (v2.6): a present
/// `context.sysctls` requires schema minor ≥ 6 (same pattern as the
/// v2.5 attribution gate), and documents AT minor ≥ 6 must carry a
/// coarse `openssl.version` (null or one of
/// [`COARSE_OPENSSL_FAMILIES`]). Earlier minors keep the historical
/// free `string|null` domain untouched (R1 finding 1: narrowing in
/// schema would reject valid older documents).
fn check_v26_sections(root: &serde_json::Map<String, serde_json::Value>) -> Result<(), String> {
    let version = root
        .get("schema_version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "doc.schema_version: expected string".to_string())?;
    // P2fix10 NEW-62: explicit minor read (no `.parse().ok()`
    // erasure — the version gate above already rejected
    // malformed/overflowing minors, so only the bare
    // implicit-.0 spelling defaults to 0 here).
    let minor: u64 = match version
        .strip_prefix("observed-crypto-v2.")
        .map(|m| m.parse::<u64>())
    {
        Some(Ok(n)) => n,
        _ => 0,
    };
    let has_sysctls = root
        .get("context")
        .and_then(|c| c.as_object())
        .is_some_and(|c| c.contains_key("sysctls"));
    if has_sysctls && minor < 6 {
        return Err(format!(
            "doc.schema_version: sysctls section needs minor >= 6, got {version:?}"
        ));
    }
    if minor >= 6 {
        let openssl = root
            .get("openssl")
            .and_then(|v| v.as_object())
            .ok_or_else(|| "doc.openssl: expected object".to_string())?;
        match openssl.get("version") {
            None | Some(serde_json::Value::Null) => {}
            Some(serde_json::Value::String(v)) if COARSE_OPENSSL_FAMILIES.contains(&v.as_str()) => {
            }
            other => {
                return Err(format!(
                    "doc.openssl.version: minor >= 6 needs a coarse family, got {other:?}"
                ));
            }
        }
    }
    Ok(())
}

/// Certified execution attribution (v2.5): every partition
/// cites a listed site plus a listed selector, segments are
/// nonzero and unique, per-site partition sums never exceed the
/// site's executed calls (checked arithmetic — overflow fails
/// closed), extrema sit inside the site's activity and the
/// guarded window, and selector/provider identities resolve to
/// listed objects. Canonical names resolve against the frozen
/// registry only (a present-but-unregistered name is malformed;
/// unknown selectors carry null). Absent sections skip;
/// present-but-malformed fails closed. Any section present
/// requires schema minor ≥ 5 (the producer upgrades exactly
/// when it projects; forward-compatible with later minors).
fn check_execution_attributions(
    root: &serde_json::Map<String, serde_json::Value>,
    bounds: ActivityBounds,
) -> Result<(), String> {
    let attributions = root.get("execution_attributions");
    let selectors = root.get("algorithm_selectors");
    let has_bounds = root.contains_key("attribution_bounds");
    if attributions.is_none() && selectors.is_none() && !has_bounds {
        return Ok(());
    }
    let version = root
        .get("schema_version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "doc.schema_version: expected string".to_string())?;
    // P2fix10 NEW-62: explicit minor read (no `.parse().ok()`
    // erasure — the version gate above already rejected
    // malformed/overflowing minors, so only the bare
    // implicit-.0 spelling defaults to 0 here).
    let minor: u64 = match version
        .strip_prefix("observed-crypto-v2.")
        .map(|m| m.parse::<u64>())
    {
        Some(Ok(n)) => n,
        _ => 0,
    };
    if minor < 5 {
        return Err(format!(
            "doc.schema_version: attribution sections need minor >= 5, got {version:?}"
        ));
    }
    let (known_ids, _) = known_objects(root)?;
    // ER-5C-I3: retain each entry's object + operation so rows
    // citing it prove the native fold's binding (not just a
    // valid index).
    let mut selector_bindings: Vec<(String, u64)> = Vec::new();
    let selector_count = match selectors {
        None => 0,
        Some(value) => {
            let items = value
                .as_array()
                .ok_or_else(|| "doc.algorithm_selectors: expected array".to_string())?;
            for (index, item) in items.iter().enumerate() {
                let ctx = format!("doc.algorithm_selectors[{index}]");
                let record = item
                    .as_object()
                    .ok_or_else(|| format!("{ctx}: expected object"))?;
                let object = record
                    .get("object")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| format!("{ctx}.object: expected string"))?;
                if !known_ids.contains(object) {
                    return Err(format!("{ctx}.object: unlisted object {object:?}"));
                }
                let operation = get_u64(record, "operation", &ctx)?;
                let id = record
                    .get("id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| format!("{ctx}.id: expected string"))?;
                if !(id.len() == 64
                    && id
                        .bytes()
                        .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f')))
                {
                    return Err(format!("{ctx}.id: expected 64 lowercase hex chars"));
                }
                match record.get("canonical_name") {
                    None | Some(serde_json::Value::Null) => {}
                    Some(name) => {
                        let name = name
                            .as_str()
                            .ok_or_else(|| format!("{ctx}.canonical_name: expected string"))?;
                        if !crate::kinds::is_known_alg(name) {
                            return Err(format!(
                                "{ctx}.canonical_name: unregistered {name:?} (unknown selectors carry null)"
                            ));
                        }
                    }
                }
                selector_bindings.push((object.to_string(), operation));
            }
            items.len() as u64
        }
    };
    // (object, device, inode, offset, generation) →
    // (calls, first_ns, last_ns) for every listed site.
    let mut sites = std::collections::BTreeMap::new();
    let mut insert = |site: &serde_json::Value, ctx: &str| -> Result<(), String> {
        let record = site
            .as_object()
            .ok_or_else(|| format!("{ctx}: expected object"))?;
        let object = record
            .get("object")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("{ctx}.object: expected string"))?
            .to_string();
        let key = (
            object,
            get_u64(record, "device", ctx)?,
            get_u64(record, "inode", ctx)?,
            get_u64(record, "offset", ctx)?,
            get_u64(record, "generation", ctx)?,
        );
        let row = (
            get_u64(record, "calls", ctx)?,
            get_u64(record, "first_ns", ctx)?,
            get_u64(record, "last_ns", ctx)?,
        );
        if sites.insert(key, row).is_some() {
            return Err(format!("{ctx}: duplicated site key"));
        }
        Ok(())
    };
    let listed = root
        .get("sites")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "doc.sites: expected array".to_string())?;
    for (index, site) in listed.iter().enumerate() {
        insert(site, &format!("doc.sites[{index}]"))?;
    }
    let fenced = root
        .get("fenced")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "doc.fenced: expected array".to_string())?;
    for (bucket, fenced_doc) in fenced.iter().enumerate() {
        let inner = fenced_doc
            .as_object()
            .and_then(|o| o.get("sites"))
            .and_then(|v| v.as_array())
            .ok_or_else(|| format!("doc.fenced[{bucket}].sites: expected array"))?;
        for (index, site) in inner.iter().enumerate() {
            insert(site, &format!("doc.fenced[{bucket}].sites[{index}]"))?;
        }
    }
    let rows = match attributions {
        None => Vec::new(),
        Some(value) => value
            .as_array()
            .ok_or_else(|| "doc.execution_attributions: expected array".to_string())?
            .clone(),
    };
    let mut segments = std::collections::BTreeSet::new();
    let mut spent: std::collections::BTreeMap<(String, u64, u64, u64, u64), u64> =
        std::collections::BTreeMap::new();
    // ER-5C-I2: document-wide assigned sum for the minimum
    // unresolved-remainder check below (checked arithmetic).
    let mut assigned = 0u64;
    for (index, item) in rows.iter().enumerate() {
        let ctx = format!("doc.execution_attributions[{index}]");
        let record = item
            .as_object()
            .ok_or_else(|| format!("{ctx}: expected object"))?;
        let object = record
            .get("object")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("{ctx}.object: expected string"))?
            .to_string();
        let key = (
            object,
            get_u64(record, "device", &ctx)?,
            get_u64(record, "inode", &ctx)?,
            get_u64(record, "offset", &ctx)?,
            get_u64(record, "generation", &ctx)?,
        );
        let (calls, first, last) = sites
            .get(&key)
            .copied()
            .ok_or_else(|| format!("{ctx}: resolves to no listed site"))?;
        let segment = get_u64(record, "segment", &ctx)?;
        if segment == 0 {
            return Err(format!("{ctx}.segment: must be nonzero"));
        }
        if !segments.insert(segment) {
            return Err(format!("{ctx}.segment: duplicated {segment}"));
        }
        let part_calls = get_u64(record, "calls", &ctx)?;
        if part_calls == 0 {
            return Err(format!("{ctx}.calls: a partition proves at least one call"));
        }
        assigned = assigned
            .checked_add(part_calls)
            .ok_or_else(|| format!("{ctx}: partition sums overflow"))?;
        let row_operation = get_u64(record, "operation", &ctx)?;
        if get_u64(record, "provider_instance", &ctx)? == 0
            || row_operation == 0
            || get_u64(record, "function", &ctx)? == 0
        {
            return Err(format!(
                "{ctx}: provider_instance/operation/function must be nonzero"
            ));
        }
        let start = get_u64(record, "start_ns", &ctx)?;
        let end = get_u64(record, "end_ns", &ctx)?;
        if start == 0 || start > end || start < first || end > last {
            return Err(format!(
                "{ctx}: extrema [{start}, {end}] escape the site activity [{first}, {last}]"
            ));
        }
        if start < bounds.start
            || match bounds.admission_end {
                Some(deadline) => end >= deadline,
                None => end > bounds.effective_end,
            }
        {
            return Err(format!(
                "{ctx}: extrema [{start}, {end}] escape the guarded window"
            ));
        }
        let scope = record
            .get("scope")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("{ctx}.scope: expected string"))?;
        if scope != crate::evidence::ATTRIBUTION_SCOPE_V1 {
            return Err(format!("{ctx}.scope: unknown {scope:?}"));
        }
        let selector = get_u64(record, "selector", &ctx)?;
        if selector >= selector_count {
            return Err(format!(
                "{ctx}.selector: {selector} indexes no listed selector"
            ));
        }
        // ER-5C-I3: the dictionary entry's object and operation
        // must equal the execution row's code object and
        // operation (the native fold's binding — an A/op3 row
        // citing a B/op4 selector is a swapped citation, never
        // a match). The range check above bounds the index.
        let (selector_object, selector_operation) = &selector_bindings[selector as usize];
        if *selector_object != key.0 {
            return Err(format!(
                "{ctx}.selector: cites a selector bound to another object"
            ));
        }
        if *selector_operation != row_operation {
            return Err(format!(
                "{ctx}.selector: cites a selector bound to another operation"
            ));
        }
        if let Some(definition) = record.get("provider_definition") {
            if !definition.is_null() {
                let definition = definition
                    .as_str()
                    .ok_or_else(|| format!("{ctx}.provider_definition: expected string"))?;
                if !known_ids.contains(definition) {
                    return Err(format!(
                        "{ctx}.provider_definition: unlisted object {definition:?}"
                    ));
                }
            }
        }
        let total = spent
            .get(&key)
            .copied()
            .unwrap_or(0)
            .checked_add(part_calls)
            .ok_or_else(|| format!("{ctx}: partition sums overflow"))?;
        spent.insert(key, total);
        if total > calls {
            return Err(format!(
                "{ctx}: partitions claim {total} calls, site executed {calls}"
            ));
        }
    }
    if has_bounds {
        let bounds_obj = root
            .get("attribution_bounds")
            .and_then(|v| v.as_object())
            .ok_or_else(|| "doc.attribution_bounds: expected object".to_string())?;
        let unresolved = get_u64(bounds_obj, "unresolved_calls", "doc.attribution_bounds")?;
        get_u64(bounds_obj, "withheld_uncertain", "doc.attribution_bounds")?;
        // ER-5C-I2: the stated bound must cover at least the
        // document-wide unassigned remainder (checked
        // arithmetic — mixed-admission collects and hand-written
        // documents understate it).
        let mut total = 0u64;
        for (calls, _, _) in sites.values() {
            total = total
                .checked_add(*calls)
                .ok_or_else(|| "doc.sites: physical call sums overflow".to_string())?;
        }
        let minimum = total.checked_sub(assigned).ok_or_else(|| {
            format!(
                "doc.attribution_bounds: partitions claim {assigned} calls, document carries {total}"
            )
        })?;
        if unresolved < minimum {
            return Err(format!(
                "doc.attribution_bounds: unresolved_calls {unresolved} understates the {minimum}-call unassigned remainder"
            ));
        }
    }
    Ok(())
}

/// Traversal object fingerprints (K3, round 2 residual O): the
/// producer guarantees lowercase hex, and the embedded semantic
/// layer enforces it (the JSON Schema carries min/maxLength only
/// — `pattern` is unsupported by the embedded validator, so
/// external validators accept any 64 chars; disclosed in the
/// schema description). Absent traversal skips; present-but-
/// malformed fails closed (the semantic layer never assumes
/// schema validation ran first).
fn check_traversal_fingerprints(
    root: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), String> {
    let Some(t) = root.get("traversal") else {
        return Ok(());
    };
    let t = t
        .as_object()
        .ok_or_else(|| "doc.traversal: expected object".to_string())?;
    for slot in ["harvest", "count", "members"] {
        let obj = t
            .get(slot)
            .and_then(|v| v.as_object())
            .ok_or_else(|| format!("doc.traversal.{slot}: expected object"))?;
        let sha = obj
            .get("sha256")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("doc.traversal.{slot}.sha256: expected string"))?;
        if !(sha.len() == 64
            && sha
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f')))
        {
            return Err(format!(
                "doc.traversal.{slot}.sha256: expected 64 lowercase hex chars"
            ));
        }
    }
    Ok(())
}

/// Legacy partition conservation (H8): the four buckets sum to
/// every counted call over current plus fenced sites.
fn check_legacy_partition(root: &serde_json::Map<String, serde_json::Value>) -> Result<(), String> {
    let part = root
        .get("legacy_partition")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "doc.legacy_partition: expected object".to_string())?;
    let sum = get_u64(part, "legacy_exclusive_calls", "doc.legacy_partition")?
        .saturating_add(get_u64(
            part,
            "non_legacy_exclusive_calls",
            "doc.legacy_partition",
        )?)
        .saturating_add(get_u64(
            part,
            "shared_ambiguous_calls",
            "doc.legacy_partition",
        )?)
        .saturating_add(get_u64(
            part,
            "unfenced_tail_calls",
            "doc.legacy_partition",
        )?);
    let total: u64 = site_calls_map(root)?
        .values()
        .fold(0, |a, c| a.saturating_add(*c));
    if sum != total {
        return Err(format!(
            "doc.legacy_partition: buckets sum to {sum} but sites count {total}"
        ));
    }
    Ok(())
}

fn sweep_forbidden_keys(v: &serde_json::Value, path: &str) -> Result<(), String> {
    match v {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                if FORBIDDEN_V2_KEYS.contains(&key.as_str()) {
                    return Err(format!("{path}: forbidden key {key:?}"));
                }
                sweep_forbidden_keys(value, &format!("{path}.{key}"))?;
            }
            Ok(())
        }
        serde_json::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                sweep_forbidden_keys(item, &format!("{path}[{index}]"))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn get_u64(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    ctx: &str,
) -> Result<u64, String> {
    obj.get(key)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| format!("{ctx}.{key}: expected u64"))
}

/// Window consistency; returns the effective bounds for
/// site-activity containment.
#[derive(Clone, Copy)]
struct ActivityBounds {
    start: u64,
    effective_end: u64,
    admission_end: Option<u64>,
}
fn check_window(
    root: &serde_json::Map<String, serde_json::Value>,
) -> Result<ActivityBounds, String> {
    let window = root
        .get("window")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "doc.window: expected object".to_string())?;
    let requested_start = get_u64(window, "requested_start_ns", "doc.window")?;
    let requested_end = get_u64(window, "requested_end_ns", "doc.window")?;
    let effective_start = get_u64(window, "effective_start_ns", "doc.window")?;
    let effective_end = get_u64(window, "effective_end_ns", "doc.window")?;
    if requested_start > requested_end {
        return Err("doc.window: requested window is inverted".to_string());
    }
    if effective_start > effective_end {
        return Err("doc.window: effective window is inverted".to_string());
    }
    // The effective window may be narrower (gaps), never wider:
    // starting the visible clock late cannot erase setup activity,
    // and counting cannot run past the request.
    if effective_start < requested_start || effective_end > requested_end {
        return Err("doc.window: effective window escapes the requested window".to_string());
    }
    let admission_end = if let Some(value) = window.get("count_admission") {
        let admission = value
            .as_object()
            .ok_or("doc.window.count_admission: expected object")?;
        if admission.len() != 2 {
            return Err("doc.window.count_admission: expected exactly start_ns/deadline_ns".into());
        }
        let start = get_u64(admission, "start_ns", "doc.window.count_admission")?;
        let deadline = get_u64(admission, "deadline_ns", "doc.window.count_admission")?;
        if start >= deadline
            || deadline > requested_end
            || effective_start != start.max(requested_start)
            || effective_end > deadline
        {
            return Err(
                "doc.window.count_admission: invalid binding to requested/effective bounds".into(),
            );
        }
        Some(deadline)
    } else {
        None
    };
    Ok(ActivityBounds {
        start: effective_start,
        effective_end,
        admission_end,
    })
}

/// (object, device, inode, offset, generation) → calls for every
/// listed site, current and fenced. Duplicate keys fail: each site
/// counts once.
type SiteCallsMap = std::collections::BTreeMap<(String, u64, u64, u64, u64), u64>;

fn site_calls_map(
    root: &serde_json::Map<String, serde_json::Value>,
) -> Result<SiteCallsMap, String> {
    let mut map = std::collections::BTreeMap::new();
    let mut insert = |site: &serde_json::Value, ctx: &str| -> Result<(), String> {
        let record = site
            .as_object()
            .ok_or_else(|| format!("{ctx}: expected object"))?;
        let object = record
            .get("object")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("{ctx}.object: expected string"))?
            .to_string();
        let key = (
            object,
            get_u64(record, "device", ctx)?,
            get_u64(record, "inode", ctx)?,
            get_u64(record, "offset", ctx)?,
            get_u64(record, "generation", ctx)?,
        );
        let calls = get_u64(record, "calls", ctx)?;
        if map.insert(key, calls).is_some() {
            return Err(format!("{ctx}: duplicated site key"));
        }
        Ok(())
    };
    let sites = root
        .get("sites")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "doc.sites: expected array".to_string())?;
    for (index, site) in sites.iter().enumerate() {
        insert(site, &format!("doc.sites[{index}]"))?;
    }
    let fenced = root
        .get("fenced")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "doc.fenced: expected array".to_string())?;
    for (bucket, fenced_doc) in fenced.iter().enumerate() {
        let inner = fenced_doc
            .as_object()
            .and_then(|o| o.get("sites"))
            .and_then(|v| v.as_array())
            .ok_or_else(|| format!("doc.fenced[{bucket}].sites: expected array"))?;
        for (index, site) in inner.iter().enumerate() {
            insert(site, &format!("doc.fenced[{bucket}].sites[{index}]"))?;
        }
    }
    Ok(map)
}

/// (object, device, inode, offset, generation, entrypoint) →
/// calls for every listed ENGINE observation. Absent when the
/// document carries no `engine_observations` key (old shape).
/// Duplicate keys fail, like sites. Each observation's object
/// triple must be listed (same two-tier error as sites) and its
/// entrypoint must index the frozen ENGINE registry with a
/// matching display name (the index is authoritative; the name is
/// checked, never trusted).
type EngineCallsMap = std::collections::BTreeMap<(String, u64, u64, u64, u64, u64), (u64, String)>;

fn engine_calls_map(
    root: &serde_json::Map<String, serde_json::Value>,
    known_triples: &std::collections::BTreeSet<(String, u64, u64)>,
    known_ids: &std::collections::BTreeSet<String>,
) -> Result<EngineCallsMap, String> {
    let mut map = std::collections::BTreeMap::new();
    let Some(items) = root.get("engine_observations") else {
        return Ok(map);
    };
    let items = items
        .as_array()
        .ok_or_else(|| "doc.engine_observations: expected array".to_string())?;
    for (index, item) in items.iter().enumerate() {
        let ctx = format!("doc.engine_observations[{index}]");
        let record = item
            .as_object()
            .ok_or_else(|| format!("{ctx}: expected object"))?;
        let object = record
            .get("object")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("{ctx}.object: expected string"))?
            .to_string();
        let triple = (
            object.clone(),
            get_u64(record, "device", &ctx)?,
            get_u64(record, "inode", &ctx)?,
        );
        if !known_triples.contains(&triple) {
            if !known_ids.contains(&object) {
                return Err(format!("{ctx}.object: unlisted object {object:?}"));
            }
            return Err(format!(
                "{ctx}: (device, inode) contradicts every record of {object:?}"
            ));
        }
        let entrypoint = get_u64(record, "entrypoint", &ctx)?;
        let want = crate::evidence::engine_name(
            u16::try_from(entrypoint).map_err(|_| format!("{ctx}.entrypoint: out of range"))?,
        )
        .ok_or_else(|| format!("{ctx}.entrypoint: outside the ENGINE registry"))?;
        let name = record
            .get("entrypoint_name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("{ctx}.entrypoint_name: expected string"))?;
        if name != want {
            return Err(format!(
                "{ctx}.entrypoint_name: {name:?} contradicts entrypoint {entrypoint} ({want:?})"
            ));
        }
        let key = (
            object,
            triple.1,
            triple.2,
            get_u64(record, "offset", &ctx)?,
            get_u64(record, "generation", &ctx)?,
            entrypoint,
        );
        let calls = get_u64(record, "calls", &ctx)?;
        let window = record
            .get("window")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("{ctx}.window: expected string"))?
            .to_string();
        if map.insert(key, (calls, window)).is_some() {
            return Err(format!("{ctx}: duplicated observation key"));
        }
    }
    Ok(map)
}

/// Registered object identities: every fingerprint plus every
/// (fingerprint, device, inode) triple.
type KnownObjects = (
    std::collections::BTreeSet<String>,
    std::collections::BTreeSet<(String, u64, u64)>,
);

/// Read the registered object identities. Shared by
/// [`check_object_refs`] and the v2.5 attribution check so the
/// two can never disagree on what is listed.
fn known_objects(
    root: &serde_json::Map<String, serde_json::Value>,
) -> Result<KnownObjects, String> {
    let objects = root
        .get("objects")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "doc.objects: expected array".to_string())?;
    // Registered (fingerprint, device, inode) triples. Matching is
    // existential over full triples, not fingerprints alone: a site
    // claiming fingerprint X at a device/inode where X was never
    // observed contradicts every object record. (Duplicate-content
    // files can share one fingerprint across inodes, so the check
    // cannot be a fingerprint → triple function.)
    let mut known_ids = std::collections::BTreeSet::new();
    let mut known_triples = std::collections::BTreeSet::new();
    for (index, object) in objects.iter().enumerate() {
        let record = object
            .as_object()
            .ok_or_else(|| format!("doc.objects[{index}]: expected object"))?;
        let id = record
            .get("id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("doc.objects[{index}].id: expected string"))?;
        known_ids.insert(id.to_string());
        known_triples.insert((
            id.to_string(),
            get_u64(record, "device", &format!("doc.objects[{index}]"))?,
            get_u64(record, "inode", &format!("doc.objects[{index}]"))?,
        ));
    }
    Ok((known_ids, known_triples))
}

fn check_object_refs(root: &serde_json::Map<String, serde_json::Value>) -> Result<(), String> {
    let (known_ids, known_triples) = known_objects(root)?;
    let check_site = |site: &serde_json::Value, ctx: &str| -> Result<(), String> {
        let record = site
            .as_object()
            .ok_or_else(|| format!("{ctx}: expected object"))?;
        let object = record
            .get("object")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("{ctx}.object: expected string"))?
            .to_string();
        let triple = (
            object.clone(),
            get_u64(record, "device", ctx)?,
            get_u64(record, "inode", ctx)?,
        );
        if !known_triples.contains(&triple) {
            if !known_ids.contains(&object) {
                return Err(format!("{ctx}.object: unlisted object {object:?}"));
            }
            return Err(format!(
                "{ctx}: (device, inode) contradicts every record of {object:?}"
            ));
        }
        let candidates = record
            .get("candidates")
            .and_then(|v| v.as_array())
            .ok_or_else(|| format!("{ctx}.candidates: expected array"))?;
        for (index, candidate) in candidates.iter().enumerate() {
            let provider = candidate
                .as_object()
                .and_then(|o| o.get("provider"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| format!("{ctx}.candidates[{index}].provider: expected string"))?;
            // Candidates carry a fingerprint only (no device/inode),
            // so provider resolution stays fingerprint-level.
            if !known_ids.contains(provider) {
                return Err(format!(
                    "{ctx}.candidates[{index}].provider: unlisted object {provider:?}"
                ));
            }
        }
        Ok(())
    };
    let sites = root
        .get("sites")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "doc.sites: expected array".to_string())?;
    for (index, site) in sites.iter().enumerate() {
        check_site(site, &format!("doc.sites[{index}]"))?;
    }
    let fenced = root
        .get("fenced")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "doc.fenced: expected array".to_string())?;
    for (bucket, fenced_doc) in fenced.iter().enumerate() {
        let inner = fenced_doc
            .as_object()
            .and_then(|o| o.get("sites"))
            .and_then(|v| v.as_array())
            .ok_or_else(|| format!("doc.fenced[{bucket}].sites: expected array"))?;
        for (index, site) in inner.iter().enumerate() {
            check_site(site, &format!("doc.fenced[{bucket}].sites[{index}]"))?;
        }
    }
    // R05: typed ENGINE observations resolve their object triple
    // like sites and their entrypoint against the frozen registry.
    let engines = engine_calls_map(root, &known_triples, &known_ids)?;
    // Policy evidence refs resolve to a listed site and, summed
    // per site within one rule, never claim more calls than that
    // site executed (the same site cited twice cannot double-claim).
    // Cross-rule citations of one site stay legal: bounds are
    // per-predicate.
    let sites = site_calls_map(root)?;
    if let Some(policy) = root.get("policy") {
        let rules = policy
            .as_object()
            .and_then(|o| o.get("rules"))
            .and_then(|v| v.as_array())
            .ok_or_else(|| "doc.policy.rules: expected array".to_string())?;
        for (rule, entry) in rules.iter().enumerate() {
            let rule_obj = entry
                .as_object()
                .ok_or_else(|| format!("doc.policy.rules[{rule}]: expected object"))?;
            // Definite matching calls can never exceed possible
            // matching calls (unknown upper bounds skip this).
            let definite = get_u64(rule_obj, "definite", &format!("doc.policy.rules[{rule}]"))?;
            if let Some(possible) = rule_obj.get("possible").and_then(|v| v.as_u64()) {
                if definite > possible {
                    return Err(format!(
                        "doc.policy.rules[{rule}]: definite {definite} exceeds possible {possible}"
                    ));
                }
            }
            let evidence = rule_obj
                .get("evidence")
                .and_then(|v| v.as_array())
                .ok_or_else(|| format!("doc.policy.rules[{rule}].evidence: expected array"))?;
            let mut claimed: std::collections::BTreeMap<(String, u64, u64, u64, u64), u64> =
                std::collections::BTreeMap::new();
            for (index, item) in evidence.iter().enumerate() {
                let ctx = format!("doc.policy.rules[{rule}].evidence[{index}]");
                let record = item
                    .as_object()
                    .ok_or_else(|| format!("{ctx}: expected object"))?;
                let object = record
                    .get("object")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| format!("{ctx}.object: expected string"))?
                    .to_string();
                let device = get_u64(record, "device", &ctx)?;
                let inode = get_u64(record, "inode", &ctx)?;
                if !known_triples.contains(&(object.clone(), device, inode)) {
                    return Err(format!("{ctx}: (object, device, inode) is unlisted"));
                }
                let key = (
                    object,
                    device,
                    inode,
                    get_u64(record, "offset", &ctx)?,
                    get_u64(record, "generation", &ctx)?,
                );
                let have = sites
                    .get(&key)
                    .ok_or_else(|| format!("{ctx}: resolves to no listed site"))?;
                let calls = get_u64(record, "calls", &ctx)?;
                let total = claimed
                    .get(&key)
                    .copied()
                    .unwrap_or(0)
                    .saturating_add(calls);
                claimed.insert(key, total);
                if total > *have {
                    return Err(format!(
                        "{ctx}: claims {total} calls across refs, site executed {have}"
                    ));
                }
            }
            // R05: engine-plane refs resolve to a listed ENGINE
            // observation with the same per-rule no-double-claim
            // rule. Absent on rules without engine evidence.
            if let Some(items) = rule_obj.get("engine_evidence") {
                let items = items.as_array().ok_or_else(|| {
                    format!("doc.policy.rules[{rule}].engine_evidence: expected array")
                })?;
                let mut eclaimed: std::collections::BTreeMap<
                    (String, u64, u64, u64, u64, u64),
                    u64,
                > = std::collections::BTreeMap::new();
                for (index, item) in items.iter().enumerate() {
                    let ctx = format!("doc.policy.rules[{rule}].engine_evidence[{index}]");
                    let record = item
                        .as_object()
                        .ok_or_else(|| format!("{ctx}: expected object"))?;
                    let object = record
                        .get("object")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| format!("{ctx}.object: expected string"))?
                        .to_string();
                    let device = get_u64(record, "device", &ctx)?;
                    let inode = get_u64(record, "inode", &ctx)?;
                    if !known_triples.contains(&(object.clone(), device, inode)) {
                        return Err(format!("{ctx}: (object, device, inode) is unlisted"));
                    }
                    let key = (
                        object,
                        device,
                        inode,
                        get_u64(record, "offset", &ctx)?,
                        get_u64(record, "generation", &ctx)?,
                        get_u64(record, "entrypoint", &ctx)?,
                    );
                    let (have, window) = engines
                        .get(&key)
                        .ok_or_else(|| format!("{ctx}: resolves to no listed observation"))?;
                    // Definite refs resolve to InWindow observations
                    // only: pre-window proves nothing about the
                    // window and untimed is never definite (policy
                    // excludes both from definite bounds).
                    if window != "in-window" {
                        return Err(format!(
                            "{ctx}: definite ref resolves to {window} observation, not in-window"
                        ));
                    }
                    let calls = get_u64(record, "calls", &ctx)?;
                    let total = eclaimed
                        .get(&key)
                        .copied()
                        .unwrap_or(0)
                        .saturating_add(calls);
                    eclaimed.insert(key, total);
                    if total > *have {
                        return Err(format!(
                            "{ctx}: claims {total} calls across refs, observation executed {have}"
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

fn check_records(
    root: &serde_json::Map<String, serde_json::Value>,
    bounds: ActivityBounds,
) -> Result<(), String> {
    // OpenSSL: verified ⟺ version present and non-empty.
    let openssl = root
        .get("openssl")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "doc.openssl: expected object".to_string())?;
    let state = openssl
        .get("state")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "doc.openssl.state: expected string".to_string())?;
    let version = openssl.get("version");
    match state {
        "verified" => {
            let text = version.and_then(|v| v.as_str()).unwrap_or("");
            if text.is_empty() {
                return Err("doc.openssl: verified without a version".to_string());
            }
        }
        "unknown" => {
            if version.is_some_and(|v| !v.is_null()) {
                return Err("doc.openssl: unknown carries a version".to_string());
            }
        }
        other => return Err(format!("doc.openssl.state: unknown {other:?}")),
    }
    // Disposition shape matches its outcome (when recorded).
    if let Some(record) = root.get("disposition") {
        let record = record
            .as_object()
            .ok_or_else(|| "doc.disposition: expected object".to_string())?;
        let outcome = record
            .get("outcome")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "doc.disposition.outcome: expected string".to_string())?;
        let code = record.get("code").is_some_and(|v| !v.is_null());
        let pid = record.get("pid").is_some_and(|v| !v.is_null());
        match outcome {
            "exited" => {
                if !code || pid {
                    return Err("doc.disposition: exited carries code only".to_string());
                }
            }
            "detached-running" | "foreign-observed" => {
                if code || !pid {
                    return Err(format!("doc.disposition: {outcome} carries pid only"));
                }
            }
            other => return Err(format!("doc.disposition.outcome: unknown {other:?}")),
        }
    }
    // Fatal kind tracks status exactly; environment carries detail.
    let status = root
        .get("completeness")
        .and_then(|v| v.as_object())
        .and_then(|o| o.get("status"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| "doc.completeness.status: expected string".to_string())?;
    let fatal_kind = root["completeness"].get("fatal_kind");
    match status {
        "FATAL" => {
            let kind = fatal_kind
                .and_then(|v| v.as_object())
                .and_then(|o| o.get("kind"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| "doc.completeness.fatal_kind: FATAL needs a kind".to_string())?;
            let detail = fatal_kind
                .and_then(|v| v.as_object())
                .and_then(|o| o.get("detail"))
                .is_some_and(|v| !v.is_null());
            match kind {
                "environment" | "runtime" => {
                    if !detail {
                        return Err(format!("doc.completeness.fatal_kind: {kind} needs detail"));
                    }
                }
                "recycled" | "attach-zero" => {
                    if detail {
                        return Err(format!(
                            "doc.completeness.fatal_kind: {kind} carries no detail"
                        ));
                    }
                }
                other => return Err(format!("doc.completeness.fatal_kind: unknown {other:?}")),
            }
        }
        "COMPLETE" | "PARTIAL" => {
            if fatal_kind.is_some_and(|v| !v.is_null()) {
                return Err(format!("doc.completeness: {status} carries a fatal kind"));
            }
        }
        other => return Err(format!("doc.completeness.status: unknown {other:?}")),
    }
    // Coverage expectation shape: applicable ⟺ site count present.
    let coverage = root
        .get("coverage")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "doc.coverage: expected array".to_string())?;
    for (index, entry) in coverage.iter().enumerate() {
        let ctx = format!("doc.coverage[{index}].expected");
        let expected = entry
            .as_object()
            .and_then(|o| o.get("expected"))
            .and_then(|v| v.as_object())
            .ok_or_else(|| format!("{ctx}: expected object"))?;
        let state = expected
            .get("state")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("{ctx}.state: expected string"))?;
        let sites = expected.get("sites").is_some_and(|v| !v.is_null());
        match state {
            "applicable" => {
                if !sites {
                    return Err(format!("{ctx}: applicable needs a site count"));
                }
            }
            "not-applicable" | "unknown" => {
                if sites {
                    return Err(format!("{ctx}: {state} carries no site count"));
                }
            }
            other => return Err(format!("{ctx}.state: unknown {other:?}")),
        }
    }
    // Site timestamps order (first touch precedes last touch)
    // with effective-window containment (F-B/Bm1: counting cannot
    // precede the clock or run past the deadline; current and
    // fenced share this closure). Bounds are inclusive: touching
    // the clock edges is ordinary.
    let check_times = |site: &serde_json::Value, ctx: &str| -> Result<(), String> {
        let record = site
            .as_object()
            .ok_or_else(|| format!("{ctx}: expected object"))?;
        let first = get_u64(record, "first_ns", ctx)?;
        let last = get_u64(record, "last_ns", ctx)?;
        if first > last {
            return Err(format!("{ctx}: first_ns {first} is past last_ns {last}"));
        }
        // A retained attachment with no calls has no activity timestamps. The
        // exact zero sentinel is not a claim that activity occurred at epoch 0.
        if get_u64(record, "calls", ctx)? == 0 && first == 0 && last == 0 {
            return Ok(());
        }
        if first < bounds.start
            || match bounds.admission_end {
                Some(deadline) => last >= deadline,
                None => last > bounds.effective_end,
            }
        {
            return Err(format!(
                "{ctx}: activity [{first}, {last}] escapes the guarded window"
            ));
        }
        if last > bounds.effective_end {
            let completeness = root
                .get("completeness")
                .and_then(|v| v.as_object())
                .ok_or("doc.completeness: expected object")?;
            let status = completeness.get("status").and_then(|v| v.as_str());
            let window = root
                .get("window")
                .and_then(|v| v.as_object())
                .ok_or("doc.window: expected object")?;
            let requested_end = get_u64(window, "requested_end_ns", "doc.window")?;
            let tail = completeness
                .get("reasons")
                .and_then(|v| v.as_array())
                .is_some_and(|reasons| {
                    reasons.iter().any(|r| {
                        r.get("kind").and_then(|v| v.as_str()) == Some("tail-gap")
                            && r.get("missing_ns").and_then(|v| v.as_u64())
                                == requested_end.checked_sub(bounds.effective_end)
                            && bounds.effective_end < requested_end
                    })
                });
            if !matches!(status, Some("PARTIAL" | "FATAL")) || !tail {
                return Err(format!(
                    "{ctx}: admission tail requires PARTIAL/FATAL and an actual coverage tail gap"
                ));
            }
        }
        Ok(())
    };
    let sites = root
        .get("sites")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "doc.sites: expected array".to_string())?;
    for (index, site) in sites.iter().enumerate() {
        check_times(site, &format!("doc.sites[{index}]"))?;
    }
    let fenced = root
        .get("fenced")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "doc.fenced: expected array".to_string())?;
    for (bucket, fenced_doc) in fenced.iter().enumerate() {
        let bucket_obj = fenced_doc
            .as_object()
            .ok_or_else(|| format!("doc.fenced[{bucket}]: expected object"))?;
        let bucket_gen = bucket_obj
            .get("generation")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| format!("doc.fenced[{bucket}].generation: expected u64"))?;
        let inner = bucket_obj
            .get("sites")
            .and_then(|v| v.as_array())
            .ok_or_else(|| format!("doc.fenced[{bucket}].sites: expected array"))?;
        for (index, site) in inner.iter().enumerate() {
            let ctx = format!("doc.fenced[{bucket}].sites[{index}]");
            check_times(site, &ctx)?;
            // Buckets group one generation: members carry the
            // bucket label (the count session versions meaning at
            // the fence instead of mixing generations).
            let member_gen = site
                .as_object()
                .and_then(|o| o.get("generation"))
                .and_then(|v| v.as_u64())
                .ok_or_else(|| format!("{ctx}.generation: expected u64"))?;
            if member_gen != bucket_gen {
                return Err(format!(
                    "{ctx}: generation {member_gen} disagrees with bucket {bucket_gen}"
                ));
            }
        }
    }
    // Status/reasons agreement: COMPLETE lists no gaps, PARTIAL
    // always names at least one. (FATAL reasons stay unconstrained:
    // a fatal input may carry no other gaps by construction.)
    let reasons = root["completeness"]
        .as_object()
        .and_then(|o| o.get("reasons"))
        .and_then(|v| v.as_array())
        .ok_or_else(|| "doc.completeness.reasons: expected array".to_string())?;
    match status {
        "COMPLETE" if !reasons.is_empty() => {
            return Err("doc.completeness: COMPLETE lists gap reasons".to_string());
        }
        "PARTIAL" if reasons.is_empty() => {
            return Err("doc.completeness: PARTIAL names no reason".to_string());
        }
        _ => {}
    }
    // COMPLETE reconciles against the underlying fields, not just
    // the reasons array (F-B/Bm1): no window gaps, no unknown or
    // short coverage, no positive loss, no executed-but-unattributed
    // calls. Each rule mirrors a `finalize` reason, so no pipeline
    // COMPLETE can trip it; PARTIAL/FATAL skip it entirely.
    if status == "COMPLETE" {
        check_complete_reconciles(root)?;
    }
    // Policy verdict is the AND of its rules: any violation rules
    // the verdict a violation, else any inconclusive rules it
    // inconclusive, else pass. `no-verdict` rides documents
    // without usable evidence only (Recycled/Environment fatals,
    // and AttachZero fatals without proved ENGINE evidence);
    // usable documents — including salvaged Runtime-fatal and
    // proved-ENGINE AttachZero ones — carry the combined verdict.
    // This consumes the shared `fatal_kind_usable` rule (the JSON
    // shape maps its validated kind token onto it — no restated
    // rule remains to drift).
    if let Some(policy) = root.get("policy") {
        let policy_obj = policy
            .as_object()
            .ok_or_else(|| "doc.policy: expected object".to_string())?;
        let verdict = policy_obj
            .get("verdict")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "doc.policy.verdict: expected string".to_string())?;
        let rules = policy_obj
            .get("rules")
            .and_then(|v| v.as_array())
            .ok_or_else(|| "doc.policy.rules: expected array".to_string())?;
        let mut results = Vec::new();
        for (index, rule) in rules.iter().enumerate() {
            results.push(
                rule.as_object()
                    .and_then(|o| o.get("result"))
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| format!("doc.policy.rules[{index}].result: expected string"))?,
            );
        }
        let combined = if results.contains(&"violation") {
            "violation"
        } else if results.contains(&"inconclusive") {
            "inconclusive"
        } else {
            "pass"
        };
        // Fatal-kind usability via the shared `fatal_kind_usable`
        // rule over the validated JSON shape (fatal kinds were
        // validated above, so this lookup cannot meet a malformed
        // kind here): Runtime, plus
        // AttachZero carrying proved ENGINE evidence (any
        // in-window observation with calls > 0 — the P2 plane the
        // attach-zero classification cannot suppress). Recycled
        // and Environment are never usable (the kind disclaims
        // carried observations).
        let fatal_kind = root["completeness"]
            .get("fatal_kind")
            .and_then(|v| v.as_object())
            .and_then(|o| o.get("kind"))
            .and_then(|v| v.as_str());
        let usable = status != "FATAL"
            || crate::evidence::fatal_kind_usable(
                crate::evidence::FatalUsabilityKind::of_token(fatal_kind.unwrap_or("")),
                json_has_proved_engine_evidence(root),
            );
        if !usable {
            if verdict != "no-verdict" {
                return Err(
                    "doc.policy: FATAL documents without usable evidence carry no-verdict"
                        .to_string(),
                );
            }
        } else if verdict == "no-verdict" {
            return Err("doc.policy: no-verdict on a document with usable evidence".to_string());
        } else if verdict != combined {
            return Err(format!(
                "doc.policy: verdict {verdict:?} contradicts rule results {results:?}"
            ));
        }
    }
    Ok(())
}

/// Proved ENGINE evidence restated over the validated JSON shape
/// (mirrors `CaptureDocument::has_proved_engine_evidence` — must
/// stay in sync): any `engine_observations` entry with calls > 0
/// and window `in-window`. Defensive over shape (a missing or
/// non-array field reads as no evidence — structural validation
/// rejects malformed shapes separately).
fn json_has_proved_engine_evidence(root: &serde_json::Map<String, serde_json::Value>) -> bool {
    root.get("engine_observations")
        .and_then(|v| v.as_array())
        .is_some_and(|items| {
            items.iter().any(|o| {
                o.get("calls").and_then(|v| v.as_u64()).unwrap_or(0) > 0
                    && o.get("window").and_then(|v| v.as_str()) == Some("in-window")
            })
        })
}

/// COMPLETE/underlying-field reconciliation (F-B/Bm1): a COMPLETE
/// verdict with an empty reasons array must also show a gapless
/// window, complete coverage, zero loss, and no unattributed
/// executions — each mirrors a `finalize` gap reason.
fn check_complete_reconciles(
    root: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), String> {
    // Gapless window: effective equals requested, no signal cut
    // (mirrors StartupGap/TailGap/SignalCut).
    let window = root
        .get("window")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "doc.window: expected object".to_string())?;
    let requested_start = get_u64(window, "requested_start_ns", "doc.window")?;
    let requested_end = get_u64(window, "requested_end_ns", "doc.window")?;
    let effective_start = get_u64(window, "effective_start_ns", "doc.window")?;
    let effective_end = get_u64(window, "effective_end_ns", "doc.window")?;
    if effective_start != requested_start || effective_end != requested_end {
        return Err("doc.completeness: COMPLETE with a narrowed effective window".to_string());
    }
    let signal_cut = window
        .get("signal_cut")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| "doc.window.signal_cut: expected bool".to_string())?;
    if signal_cut {
        return Err("doc.completeness: COMPLETE with signal_cut".to_string());
    }
    // Complete coverage: no unknown denominators, no applicable
    // shortfalls (mirrors UnknownDenominator/UndiscoveredSites/
    // UnattachedSites).
    let coverage = root
        .get("coverage")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "doc.coverage: expected array".to_string())?;
    for (index, entry) in coverage.iter().enumerate() {
        let ctx = format!("doc.coverage[{index}]");
        let record = entry
            .as_object()
            .ok_or_else(|| format!("{ctx}: expected object"))?;
        let expected = record
            .get("expected")
            .and_then(|v| v.as_object())
            .ok_or_else(|| format!("{ctx}.expected: expected object"))?;
        let state = expected
            .get("state")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("{ctx}.expected.state: expected string"))?;
        match state {
            "unknown" => {
                return Err(format!("{ctx}: COMPLETE with an unknown denominator"));
            }
            "applicable" => {
                let sites = expected
                    .get("sites")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| format!("{ctx}.expected.sites: expected u64"))?;
                let discovered = get_u64(record, "discovered", &ctx)?;
                let attached = get_u64(record, "attached", &ctx)?;
                if discovered < sites || attached < sites {
                    return Err(format!(
                        "{ctx}: COMPLETE with undiscovered/unattached sites"
                    ));
                }
            }
            _ => {}
        }
    }
    // Zero loss: no positive Loss-kind counter (mirrors Loss).
    let completeness = root
        .get("completeness")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "doc.completeness: expected object".to_string())?;
    let counters = completeness
        .get("counters")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "doc.completeness.counters: expected array".to_string())?;
    for (index, counter) in counters.iter().enumerate() {
        let ctx = format!("doc.completeness.counters[{index}]");
        let record = counter
            .as_object()
            .ok_or_else(|| format!("{ctx}: expected object"))?;
        let kind = record
            .get("kind")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("{ctx}.kind: expected string"))?;
        if kind == "loss" && get_u64(record, "value", &ctx)? > 0 {
            return Err(format!("{ctx}: COMPLETE with positive loss"));
        }
    }
    // No unattributed executions (mirrors UnattributedCalls):
    // calls>0 with an unknown candidate set, current and fenced.
    let check_site = |site: &serde_json::Value, ctx: &str| -> Result<(), String> {
        let record = site
            .as_object()
            .ok_or_else(|| format!("{ctx}: expected object"))?;
        let calls = get_u64(record, "calls", ctx)?;
        if calls == 0 {
            return Ok(());
        }
        let candidates_coverage = record
            .get("candidates_coverage")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("{ctx}.candidates_coverage: expected string"))?;
        if candidates_coverage == "unknown" {
            return Err(format!("{ctx}: COMPLETE with unattributed calls"));
        }
        Ok(())
    };
    let sites = root
        .get("sites")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "doc.sites: expected array".to_string())?;
    for (index, site) in sites.iter().enumerate() {
        check_site(site, &format!("doc.sites[{index}]"))?;
    }
    let fenced = root
        .get("fenced")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "doc.fenced: expected array".to_string())?;
    for (bucket, fenced_doc) in fenced.iter().enumerate() {
        let inner = fenced_doc
            .as_object()
            .and_then(|o| o.get("sites"))
            .and_then(|v| v.as_array())
            .ok_or_else(|| format!("doc.fenced[{bucket}].sites: expected array"))?;
        for (index, site) in inner.iter().enumerate() {
            check_site(site, &format!("doc.fenced[{bucket}].sites[{index}]"))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_schema_claim_spellings() {
        // P2fix19 NEW-119: the explicit-discriminator scan
        // claims on the canonical spelling, spaced
        // spellings, and truncated/binary tails — and on
        // nothing else (wrong value, non-string value, or
        // a tear inside the discriminator itself).
        let s = "osslscope-checkpoint-settled-v1";
        assert!(super::raw_contains_schema_claim(
            b"{\"schema\":\"osslscope-checkpoint-settled-v1\",\"x\":1}".as_slice(),
            s
        ));
        assert!(super::raw_contains_schema_claim(
            b"{ \"schema\" : \"osslscope-checkpoint-settled-v1\" ,".as_slice(),
            s
        ));
        assert!(super::raw_contains_schema_claim(
            b"{\"schema\":\"osslscope-checkpoint-settled-v1\",".as_slice(),
            s
        ));
        assert!(super::raw_contains_schema_claim(
            b"{\"schema\":\"osslscope-checkpoint-settled-v1\",\xff\xfe".as_slice(),
            s
        ));
        assert!(!super::raw_contains_schema_claim(
            b"{\"schema\":\"other-schema-v1\"}".as_slice(),
            s
        ));
        assert!(!super::raw_contains_schema_claim(
            b"{\"schema\":5}".as_slice(),
            s
        ));
        assert!(!super::raw_contains_schema_claim(
            b"{\"schema\":\"osslscope-checkpoint-settled-".as_slice(),
            s
        ));
        assert!(!super::raw_contains_schema_claim(
            b"not json at all".as_slice(),
            s
        ));
        assert!(!super::raw_contains_schema_claim(b"".as_slice(), s));
    }

    #[test]
    fn compat_matrix() {
        assert!(check_version("observed-crypto-v1.0"));
        assert!(check_version("observed-crypto-v1.9"));
        assert!(check_version("observed-crypto-v1"));
        assert!(!check_version("observed-crypto-v2.0"));
        assert!(!check_version("observed-crypto-v0.9"));
        assert!(!check_version("0.2-provisional"));
        assert!(!check_version(""));
        assert!(!check_version("observed-crypto-v1.x"));
        assert!(!check_version("observed-crypto-vX"));
        assert!(!check_version("1.0"));
    }

    #[test]
    fn request_evidence_gate_pins_binding_and_activation() {
        // Phase 1 (v2.8): the producer-shaped section passes; a
        // mismatched export/capability, candidates != success, a
        // manufactured activation, and an old minor all fail.
        // GATE (fix1): the gate shares the typed strict validation
        // (shapes, duplicates, order, partitions) and reconciles the
        // remainder against api_activity, pinning the v2.8 trigger.
        use serde_json::json;
        let coverage_all = || {
            json!([
                {"surface_id": 10, "observed": true},
                {"surface_id": 11, "observed": true},
                {"surface_id": 12, "observed": true},
                {"surface_id": 13, "observed": true},
                {"surface_id": 14, "observed": true},
                {"surface_id": 15, "observed": true},
                {"surface_id": 73, "observed": true},
                {"surface_id": 74, "observed": true},
                {"surface_id": 75, "observed": true},
                {"surface_id": 76, "observed": true},
                {"surface_id": 77, "observed": true},
                {"surface_id": 78, "observed": true},
                {"surface_id": 79, "observed": true},
                {"surface_id": 80, "observed": true},
            ])
        };
        // GATE-OPEN + NEW-16 fix5: the default shape is the
        // producer's windowed form — zero claims ride a bound
        // nonempty silence interval, so every accept case carries
        // one and every reject case below fails on its CITED
        // defect (never on a missing interval).
        let section_full = |fetches: serde_json::Value,
                            loads: serde_json::Value,
                            activation: &str,
                            coverage: serde_json::Value,
                            queries: serde_json::Value,
                            adverts: serde_json::Value,
                            unattributed: serde_json::Value,
                            activity: serde_json::Value|
         -> serde_json::Map<String, serde_json::Value> {
            json!({
                "schema_version": "observed-crypto-v2.8",
                "api_activity": activity,
                "window": {"effective_start_ns": 100, "effective_end_ns": 200},
                "request_evidence": {
                    "version": 1,
                    "silence_window": {"start_ns": 100, "end_ns": 200},
                    "fetches": fetches,
                    "fetch_coverage": coverage,
                    "loads": loads,
                    "inits": {"success": 0, "failure": 0, "unknown": 0},
                    "queries": queries,
                    "advertisements": adverts,
                    "default_activation": activation,
                    "unattributed": unattributed,
                },
            })
            .as_object()
            .unwrap()
            .clone()
        };
        let section = |fetches: serde_json::Value,
                       loads: serde_json::Value,
                       activation: &str|
         -> serde_json::Map<String, serde_json::Value> {
            section_full(
                fetches,
                loads,
                activation,
                coverage_all(),
                json!([]),
                json!([]),
                json!("unknown"),
                json!([]),
            )
        };
        let fetch76 = json!({
            "surface_id": 76, "export": "EVP_RAND_fetch",
            "capability": {"evp": {"operation": "rand"}},
            "attempts": 1, "success": 1, "failure": 0, "unknown": 0,
            "properties": "not_captured",
        });
        let load_default = json!({
            "name": "default", "attempts": 1, "success": 1,
            "failure": 0, "unknown": 0, "candidates": 1, "tier": "candidate",
        });
        assert!(
            check_request_evidence(&section(
                json!([fetch76]),
                json!([load_default]),
                "load_observed"
            ))
            .is_ok()
        );
        assert!(check_request_evidence(&section(json!([]), json!([]), "unknown")).is_ok());
        // Mismatched export for surface 76.
        let mut bad = fetch76.clone();
        bad["export"] = json!("EVP_MD_fetch");
        assert!(check_request_evidence(&section(json!([bad]), json!([]), "unknown")).is_err());
        // Mismatched capability for surface 76.
        let mut bad = fetch76.clone();
        bad["capability"] = json!({"evp": {"operation": "digest"}});
        assert!(check_request_evidence(&section(json!([bad]), json!([]), "unknown")).is_err());
        // candidates != success.
        let mut bad = load_default.clone();
        bad["candidates"] = json!(2);
        assert!(
            check_request_evidence(&section(json!([]), json!([bad]), "load_observed")).is_err()
        );
        // Manufactured activation: load_observed with no default success.
        assert!(check_request_evidence(&section(json!([]), json!([]), "load_observed")).is_err());
        // ... and unknown despite a default success.
        assert!(
            check_request_evidence(&section(json!([]), json!([load_default]), "unknown")).is_err()
        );
        // Old minor carrying the section.
        let mut root = section(json!([]), json!([]), "unknown");
        root.insert("schema_version".to_string(), json!("observed-crypto-v2.7"));
        assert!(check_request_evidence(&root).is_err());
        // Absent sections skip on old minors.
        let root = json!({"schema_version": "observed-crypto-v2.4"})
            .as_object()
            .unwrap()
            .clone();
        assert!(check_request_evidence(&root).is_ok());
        // GATE: surface 78 with an `evp` object (right word, wrong
        // shape — the v2.8 producer trigger for this exact case).
        let shape78 = json!({
            "surface_id": 78, "export": "OSSL_DECODER_fetch",
            "capability": {"evp": {"operation": "decoder"}},
            "attempts": 1, "success": 1, "failure": 0, "unknown": 0,
            "properties": "not_captured",
        });
        assert!(check_request_evidence(&section(json!([shape78]), json!([]), "unknown")).is_err());
        // GATE: duplicate fetch IDs rejected.
        assert!(
            check_request_evidence(&section(
                json!([fetch76.clone(), fetch76.clone()]),
                json!([]),
                "unknown"
            ))
            .is_err()
        );
        // GATE: out-of-order fetch IDs rejected (canonical ID order).
        let fetch10 = json!({
            "surface_id": 10, "export": "EVP_MD_fetch",
            "capability": {"evp": {"operation": "digest"}},
            "attempts": 1, "success": 1, "failure": 0, "unknown": 0,
            "properties": "not_captured",
        });
        assert!(
            check_request_evidence(&section(
                json!([fetch76.clone(), fetch10.clone()]),
                json!([]),
                "unknown"
            ))
            .is_err()
        );
        assert!(
            check_request_evidence(&section(json!([fetch10, fetch76]), json!([]), "unknown"))
                .is_ok()
        );
        // GATE: unmatched attempt/result edges are legitimate (never forced).
        let mut unmatched = fetch76.clone();
        unmatched["success"] = json!(0);
        assert!(check_request_evidence(&section(json!([unmatched]), json!([]), "unknown")).is_ok());
        // GATE-OPEN + NEW-22 fix6: an explicit all-zero fetch row
        // (fabricated — the producer never emits one) is rejected
        // even with observed coverage and a bound interval, while a
        // single nonzero count (unmatched result) stays legitimate.
        let mut zero = fetch76.clone();
        zero["attempts"] = json!(0);
        zero["success"] = json!(0);
        zero["failure"] = json!(0);
        zero["unknown"] = json!(0);
        assert!(
            check_request_evidence(&section(json!([zero]), json!([]), "unknown")).is_err(),
            "the document gate must reject an explicit all-zero fetch row"
        );
        let mut result_only = fetch76.clone();
        result_only["attempts"] = json!(0);
        result_only["failure"] = json!(0);
        result_only["unknown"] = json!(0);
        assert!(
            check_request_evidence(&section(json!([result_only]), json!([]), "unknown")).is_ok(),
            "an unmatched result stays legitimate"
        );
        // GATE: capability extras rejected.
        let mut extra = fetch76.clone();
        extra["capability"] = json!({"evp": {"operation": "rand", "smuggled": 1}});
        assert!(check_request_evidence(&section(json!([extra]), json!([]), "unknown")).is_err());
        // GATE: a present row without coverage rejected.
        let mut uncovered = coverage_all();
        uncovered[9]["observed"] = json!(false);
        assert!(
            check_request_evidence(&section_full(
                json!([fetch76]),
                json!([]),
                "unknown",
                uncovered,
                json!([]),
                json!([]),
                json!("unknown"),
                json!([]),
            ))
            .is_err()
        );
        // GATE: unequal query partitions rejected; equal accepted.
        let query_bad = json!({
            "operation": "digest",
            "wrapper": {"success": 1, "failure": 0, "unknown": 0,
                        "cacheable": 2, "volatile": 0, "cache_unknown": 0},
            "callback": {"success": 0, "failure": 0, "unknown": 0,
                         "cacheable": 0, "volatile": 0, "cache_unknown": 0},
        });
        assert!(
            check_request_evidence(&section_full(
                json!([]),
                json!([]),
                "unknown",
                coverage_all(),
                json!([query_bad]),
                json!([]),
                json!("unknown"),
                json!([]),
            ))
            .is_err()
        );
        let query_good = json!({
            "operation": "digest",
            "wrapper": {"success": 1, "failure": 0, "unknown": 0,
                        "cacheable": 1, "volatile": 0, "cache_unknown": 0},
            "callback": {"success": 0, "failure": 0, "unknown": 1,
                         "cacheable": 0, "volatile": 0, "cache_unknown": 1},
        });
        assert!(
            check_request_evidence(&section_full(
                json!([]),
                json!([]),
                "unknown",
                coverage_all(),
                json!([query_good]),
                json!([]),
                json!("unknown"),
                json!([]),
            ))
            .is_ok()
        );
        // GATE: duplicate query/advert operations rejected.
        assert!(
            check_request_evidence(&section_full(
                json!([]),
                json!([]),
                "unknown",
                coverage_all(),
                json!([query_good.clone(), query_good.clone()]),
                json!([]),
                json!("unknown"),
                json!([]),
            ))
            .is_err()
        );
        let advert = json!({"operation": "digest", "count": 1, "tier": "candidate"});
        assert!(
            check_request_evidence(&section_full(
                json!([]),
                json!([]),
                "unknown",
                coverage_all(),
                json!([]),
                json!([advert.clone(), advert.clone()]),
                json!("unknown"),
                json!([]),
            ))
            .is_err()
        );
        // GATE: duplicate/out-of-order load names rejected.
        let load_legacy = json!({
            "name": "legacy", "attempts": 1, "success": 0,
            "failure": 1, "unknown": 0, "candidates": 0, "tier": "candidate",
        });
        assert!(
            check_request_evidence(&section(
                json!([]),
                json!([load_legacy.clone(), load_default.clone()]),
                "load_observed",
            ))
            .is_err(),
            "legacy before default is out of canonical order"
        );
        assert!(
            check_request_evidence(&section(
                json!([]),
                json!([load_default.clone(), load_default.clone()]),
                "load_observed",
            ))
            .is_err(),
            "duplicate load names rejected"
        );
        // GATE: remainder reconciles against api_activity (invented
        // remainders rejected; exact matches accepted).
        let activity = json!([
            {"api": 20, "entries": 2},
            {"api": 21, "entries": 3},
        ]);
        assert!(
            check_request_evidence(&section_full(
                json!([]),
                json!([]),
                "unknown",
                coverage_all(),
                json!([]),
                json!([]),
                json!({"observed": {"ops": 4}}),
                activity.clone(),
            ))
            .is_err(),
            "invented remainder (4 != 2+3) rejected"
        );
        assert!(
            check_request_evidence(&section_full(
                json!([]),
                json!([]),
                "unknown",
                coverage_all(),
                json!([]),
                json!([]),
                json!({"observed": {"ops": 5}}),
                activity,
            ))
            .is_ok(),
            "exact remainder accepted"
        );
        // GATE: Unknown with positive entries rejected (positives are
        // preserved, never demoted to Unknown).
        assert!(
            check_request_evidence(&section_full(
                json!([]),
                json!([]),
                "unknown",
                coverage_all(),
                json!([]),
                json!([]),
                json!("unknown"),
                json!([{"api": 20, "entries": 1}]),
            ))
            .is_err()
        );
        // GATE-OPEN + PINS/NEW-12 fix4: an observed zero needs a
        // serialized successful-read receipt behind it — empty or
        // entirely-unreceipted activity rejects; one receipted row
        // accepts. The attachment bit alone receipts NOTHING (a
        // failed read keeps it but carries no receipt).
        assert!(
            check_request_evidence(&section_full(
                json!([]),
                json!([]),
                "unknown",
                coverage_all(),
                json!([]),
                json!([]),
                json!({"observed": {"ops": 0}}),
                json!([]),
            ))
            .is_err(),
            "observed zero with empty activity rejected"
        );
        assert!(
            check_request_evidence(&section_full(
                json!([]),
                json!([]),
                "unknown",
                coverage_all(),
                json!([]),
                json!([]),
                json!({"observed": {"ops": 0}}),
                json!([
                    {"api": 20, "entries": 0, "gaps": {"not_attached": true, "read_receipt": false}},
                    {"api": 35, "entries": 0, "gaps": {"not_attached": true, "read_receipt": false}},
                ]),
            ))
            .is_err(),
            "observed zero with entirely-unavailable activity rejected"
        );
        assert!(
            check_request_evidence(&section_full(
                json!([]),
                json!([]),
                "unknown",
                coverage_all(),
                json!([]),
                json!([]),
                json!({"observed": {"ops": 0}}),
                json!([
                    {"api": 20, "entries": 0, "gaps": {"not_attached": false, "read_receipt": false}},
                    {"api": 35, "entries": 0, "gaps": {"not_attached": true, "read_receipt": false}},
                ]),
            ))
            .is_err(),
            "observed zero with attached-but-unreceipted rows rejected (attachment alone receipts nothing)"
        );
        assert!(
            check_request_evidence(&section_full(
                json!([]),
                json!([]),
                "unknown",
                coverage_all(),
                json!([]),
                json!([]),
                json!({"observed": {"ops": 0}}),
                json!([
                    {"api": 20, "entries": 0, "gaps": {"not_attached": false, "read_receipt": true}},
                    {"api": 35, "entries": 0, "gaps": {"not_attached": true, "read_receipt": false}},
                ]),
            ))
            .is_ok(),
            "observed zero with one receipted row accepted (armed idle)"
        );
        // NEW-9 fix4: the published silence interval binds inside
        // the document's effective window — a silence claim
        // outside the capture window (or without one) is
        // incoherent, and an inverted interval never parses.
        let windowed = |start: u64, end: u64| {
            let mut doc = section_full(
                json!([]),
                json!([]),
                "unknown",
                coverage_all(),
                json!([]),
                json!([]),
                json!({"observed": {"ops": 0}}),
                json!([
                    {"api": 20, "entries": 0, "gaps": {"not_attached": false, "read_receipt": true}},
                ]),
            );
            doc.insert(
                "window".to_string(),
                json!({"effective_start_ns": 100, "effective_end_ns": 200}),
            );
            doc["request_evidence"]["silence_window"] = json!({"start_ns": start, "end_ns": end});
            doc
        };
        assert!(
            check_request_evidence(&windowed(150, 200)).is_ok(),
            "silence inside the effective window accepted"
        );
        assert!(
            check_request_evidence(&windowed(50, 200)).is_err(),
            "silence starting before the capture window rejected"
        );
        assert!(
            check_request_evidence(&windowed(150, 250)).is_err(),
            "silence ending past the capture window rejected"
        );
        assert!(
            check_request_evidence(&windowed(200, 150)).is_err(),
            "inverted silence interval rejected"
        );
        let mut nowrap = windowed(150, 200);
        nowrap.remove("window");
        assert!(
            check_request_evidence(&nowrap).is_err(),
            "a silence claim without a capture window rejected (fail closed)"
        );
        // GATE-OPEN + NEW-9-OPEN + NEW-16 fix5: zero claims with an
        // ABSENT or EMPTY silence interval are rejected (the full
        // gate used to accept them) — both the observed-zero
        // remainder and covered-but-absent surfaces — while
        // positive-only evidence without an interval stays valid.
        let unbacked_zero = || {
            let mut doc = section_full(
                json!([]),
                json!([]),
                "unknown",
                coverage_all(),
                json!([]),
                json!([]),
                json!({"observed": {"ops": 0}}),
                json!([
                    {"api": 20, "entries": 0, "gaps": {"not_attached": false, "read_receipt": true}},
                ]),
            );
            doc["request_evidence"]
                .as_object_mut()
                .unwrap()
                .remove("silence_window");
            doc
        };
        assert!(
            check_request_evidence(&unbacked_zero()).is_err(),
            "an observed zero without a silence interval rejected (receipted rows or not)"
        );
        let mut unbacked_surface = section(json!([]), json!([]), "unknown");
        unbacked_surface["request_evidence"]
            .as_object_mut()
            .unwrap()
            .remove("silence_window");
        assert!(
            check_request_evidence(&unbacked_surface).is_err(),
            "covered-but-absent surfaces without a silence interval rejected"
        );
        assert!(
            check_request_evidence(&windowed(150, 150)).is_err(),
            "an empty silence interval rejected (certifies nothing)"
        );
        // Positive-only evidence without an interval: valid (batch
        // shape — one edged surface, positive remainder, no zeros).
        let mut edged_only = coverage_all();
        for (index, row) in edged_only.as_array_mut().unwrap().iter_mut().enumerate() {
            row["observed"] = json!(index == 9);
        }
        let mut positive_only = section_full(
            json!([fetch76]),
            json!([]),
            "unknown",
            edged_only,
            json!([]),
            json!([]),
            json!({"observed": {"ops": 5}}),
            json!([{"api": 20, "entries": 5}]),
        );
        positive_only["request_evidence"]
            .as_object_mut()
            .unwrap()
            .remove("silence_window");
        assert!(
            check_request_evidence(&positive_only).is_ok(),
            "positive-only evidence without an interval stays valid"
        );
        // GATE: the v2.8 producer trigger pins both directions at
        // minor 8 exactly — v2.8 without the section is rejected
        // (nothing else stamps 8; NEW-4 narrows the reverse leg to 8).
        let bare28 = json!({
            "schema_version": "observed-crypto-v2.8",
            "api_activity": [],
        })
        .as_object()
        .unwrap()
        .clone();
        assert!(check_request_evidence(&bare28).is_err());
        // NEW-4: the reverse trigger applies to the CURRENT v2.8
        // stamp only — a later minor emitted for an unrelated
        // optional feature validates WITHOUT this section, and a
        // later minor carrying the section still validates it
        // (valid accepts, invalid rejects — never skipped).
        let bare29 = json!({
            "schema_version": "observed-crypto-v2.9",
            "api_activity": [],
        })
        .as_object()
        .unwrap()
        .clone();
        assert!(
            check_request_evidence(&bare29).is_ok(),
            "v2.9 without the section validates (reverse trigger is v2.8-only)"
        );
        let mut with29 = section(json!([]), json!([]), "unknown");
        with29.insert("schema_version".to_string(), json!("observed-crypto-v2.9"));
        assert!(
            check_request_evidence(&with29).is_ok(),
            "v2.9 with a valid section validates"
        );
        let mut bad29 = section_full(
            json!([]),
            json!([load_default]),
            "unknown",
            coverage_all(),
            json!([]),
            json!([]),
            json!("unknown"),
            json!([]),
        );
        bad29.insert("schema_version".to_string(), json!("observed-crypto-v2.9"));
        assert!(
            check_request_evidence(&bad29).is_err(),
            "v2.9 with an invalid section still rejects (unknown despite default success)"
        );
        // NEW-27 fix7: the published schema requires an OBJECT when
        // `silence_window` is present — the document gate rejects a
        // positional `[start, end]` array and an explicit `null`
        // (where omission is legal) alongside the valid omission +
        // object cases (shared decode with the typed reader).
        let mut omitted = section(json!([]), json!([]), "unknown");
        // Omission is legal only with no zero claim: all coverage
        // unobserved, unknown remainder, no rows.
        let mut dark = coverage_all();
        for row in dark.as_array_mut().unwrap().iter_mut() {
            row["observed"] = json!(false);
        }
        omitted["request_evidence"]["fetch_coverage"] = dark;
        omitted["request_evidence"]
            .as_object_mut()
            .unwrap()
            .remove("silence_window");
        assert!(
            check_request_evidence(&omitted).is_ok(),
            "omission with no zero claim stays valid"
        );
        let mut nulled = omitted.clone();
        nulled["request_evidence"]["silence_window"] = json!(null);
        assert!(
            check_request_evidence(&nulled).is_err(),
            "the document gate must reject an explicit null silence_window"
        );
        let mut arrayed = omitted.clone();
        arrayed["request_evidence"]["silence_window"] = json!([100, 200]);
        assert!(
            check_request_evidence(&arrayed).is_err(),
            "the document gate must reject a positional silence_window array"
        );
        assert!(
            check_request_evidence(&section(json!([]), json!([]), "unknown")).is_ok(),
            "the object shape stays valid"
        );
    }

    #[test]
    fn trace_summary_gate_pins_trigger_and_coherence() {
        // Phase 2 (v2.9): a real producer fold summarizes, stamps,
        // and passes; version/mode/conservation/bucket/binding
        // mutations and both trigger directions fail.
        use crate::provider_observation::trace as t;
        use serde_json::json;
        let mut p = t::TraceProducer::new();
        p.set_mode(t::TRACE_MODE_LATENCY);
        let k = t::PairKey {
            pid: 1,
            tid: 2,
            generation: 1,
            cookie: 9,
            invocation: 1,
        };
        p.attempt(t::AttemptEdge {
            key: k,
            api: 20,
            monotonic_ns: 1000,
            start_time_ns: 1,
            seed: 1,
        });
        p.result(t::ResultEdge {
            key: k,
            api: 20,
            monotonic_ns: 1500,
            outcome: 1,
            start_time_ns: 1,
            seed: 1,
        });
        let window = p.close_window(0, 9000, [0; 8]);
        let totals = p.totals();
        let summary = t::summarize(&window, &totals, "latency", None);
        summary.validate().expect("real fold validates");
        let root = |version: &str, section: serde_json::Value| {
            let mut map = serde_json::Map::new();
            map.insert("schema_version".to_string(), json!(version));
            if !section.is_null() {
                map.insert("trace_summary".to_string(), section);
            }
            map
        };
        let good = serde_json::to_value(&summary).unwrap();
        assert!(check_trace_summary(&root("observed-crypto-v2.9", good.clone())).is_ok());
        // Later minors validate it when present, skip when absent.
        assert!(check_trace_summary(&root("observed-crypto-v2.10", good.clone())).is_ok());
        assert!(check_trace_summary(&root("observed-crypto-v2.10", json!(null))).is_ok());
        assert!(check_trace_summary(&root("observed-crypto-v2.8", json!(null))).is_ok());
        // Trigger directions.
        assert!(check_trace_summary(&root("observed-crypto-v2.9", json!(null))).is_err());
        assert!(check_trace_summary(&root("observed-crypto-v2.8", good.clone())).is_err());
        // Coherence mutations (each fails on its cited defect).
        let mut bad = good.clone();
        bad["version"] = json!(2);
        assert!(check_trace_summary(&root("observed-crypto-v2.9", bad)).is_err());
        let mut bad = good.clone();
        bad["mode"] = json!("turbo");
        assert!(check_trace_summary(&root("observed-crypto-v2.9", bad)).is_err());
        let mut bad = good.clone();
        bad["window"]["class_window"]["success"] = json!(99);
        assert!(check_trace_summary(&root("observed-crypto-v2.9", bad)).is_err());
        let mut bad = good.clone();
        bad["histograms"]["success"]["buckets"][18] = json!(99);
        assert!(check_trace_summary(&root("observed-crypto-v2.9", bad)).is_err());
        let mut bad = good.clone();
        bad["histograms"] = json!(null);
        assert!(check_trace_summary(&root("observed-crypto-v2.9", bad)).is_err());
        // Status mode carries no histograms.
        let status = t::summarize(&window, &totals, "status", None);
        assert!(status.histograms.is_none());
        let status_v = serde_json::to_value(&status).unwrap();
        assert!(check_trace_summary(&root("observed-crypto-v2.9", status_v.clone())).is_ok());
        let mut bad = status_v;
        bad["histograms"] = good["histograms"].clone();
        assert!(check_trace_summary(&root("observed-crypto-v2.9", bad)).is_err());
        // Off/metadata ride fallback only.
        let mut bad = good.clone();
        bad["mode"] = json!("off");
        bad["fallback"] = json!(false);
        assert!(check_trace_summary(&root("observed-crypto-v2.9", bad)).is_err());
        // Uncertain epochs withhold (same rule as the typed gate):
        // a latency summary with withheld classes/distributions
        // passes; a mismatched one fails.
        p.reject_unknown();
        let wu = p.close_window(1, 9900, [0; 8]);
        let tu = p.totals();
        let withheld = t::summarize(&wu, &tu, "latency", None);
        assert!(withheld.pairing_uncertain);
        let withheld_v = serde_json::to_value(&withheld).unwrap();
        assert!(check_trace_summary(&root("observed-crypto-v2.9", withheld_v.clone())).is_ok());
        let mut bad = withheld_v;
        bad["class_epoch"] = good["class_epoch"].clone();
        assert!(check_trace_summary(&root("observed-crypto-v2.9", bad)).is_err());
    }

    #[test]
    fn new4_duplicate_diagnostics_name_path_not_key() {
        // P2fix4 NEW-4: duplicate-field rejections name the
        // containing PATH, never the rejected key text (a canary
        // key must not echo into diagnostics).
        let err =
            check_envelope_raw_duplicates(r#"{"CANARY_K3Y_N0ECHO": 1, "CANARY_K3Y_N0ECHO": 2}"#)
                .expect_err("duplicated canary key must reject");
        assert!(err.contains("duplicate field"), "{err}");
        assert!(
            !err.contains("CANARY_K3Y_N0ECHO"),
            "key must not echo: {err}"
        );
        let err = check_trace_summary_raw_duplicates(
            r#"{"trace_summary": {"CANARY_K3Y_N0ECHO": 1, "CANARY_K3Y_N0ECHO": 2}}"#,
        )
        .expect_err("duplicated section key must reject");
        assert!(err.contains("duplicate field"), "{err}");
        assert!(
            !err.contains("CANARY_K3Y_N0ECHO"),
            "key must not echo: {err}"
        );
    }

    #[test]
    fn new25_duplicate_diagnostics_echo_no_ancestor_keys() {
        // P2fix5 NEW-25: duplicate diagnostics use FIXED field
        // identifiers (caller roots) + STRUCTURAL positions — raw
        // ancestor keys never echo (pre-fix: the walked path joins
        // raw input keys, so a canary in any ANCESTOR position
        // echoes; the fix4 pin only covered the duplicate key
        // itself).
        for (what, text, check) in [
            (
                "envelope",
                r#"{"CANARY_ANCESTOR_N0ECHO": {"x": 1, "x": 2}}"#,
                check_envelope_raw_duplicates as fn(&str) -> Result<(), String>,
            ),
            (
                "trace",
                r#"{"trace_summary": {"CANARY_ANCESTOR_N0ECHO": {"x": 1, "x": 2}}}"#,
                check_trace_summary_raw_duplicates as fn(&str) -> Result<(), String>,
            ),
            (
                "request-evidence",
                r#"{"request_evidence": {"CANARY_ANCESTOR_N0ECHO": {"x": 1, "x": 2}}}"#,
                check_request_evidence_raw_duplicates as fn(&str) -> Result<(), String>,
            ),
            (
                "api-activity",
                r#"{"api_activity": [{"CANARY_ANCESTOR_N0ECHO": {"x": 1, "x": 2}}]}"#,
                check_api_activity_raw_duplicates as fn(&str) -> Result<(), String>,
            ),
            (
                "otlp",
                r#"{"CANARY_ANCESTOR_N0ECHO": {"x": 1, "x": 2}}"#,
                check_otlp_response_raw_duplicates as fn(&str) -> Result<(), String>,
            ),
            (
                "array-nesting",
                r#"{"arr": [{"CANARY_ANCESTOR_N0ECHO": {"x": 1, "x": 2}}]}"#,
                check_envelope_raw_duplicates as fn(&str) -> Result<(), String>,
            ),
        ] {
            let err = check(text).expect_err(&format!("{what}: nested dup must reject"));
            assert!(err.contains("duplicate field"), "{what}: {err}");
            assert!(
                !err.contains("CANARY_ANCESTOR_N0ECHO"),
                "{what}: ancestor key must not echo: {err}"
            );
            assert!(
                !err.contains("\"x\""),
                "{what}: dup key must not echo: {err}"
            );
        }
    }

    #[test]
    fn trace_summary_raw_duplicates_reject() {
        // P2fix1 item 23: duplicate keys under `trace_summary`
        // (notably a doubled by_api identity) reject on the RAW
        // text — the collapsed `Value` path is blind (last-wins).
        // Both text shapes covered: document text + envelope bytes.
        let text = r#"{"trace_summary":{"version":1,"mode":"latency","fallback":false,"by_api":{"20":{"success":{"buckets":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"sum":5,"count":1}}},"window":{"window_seq":0,"mode":"latency","fallback":false,"paired":0,"trace_unpaired_entries":0,"trace_unpaired_results":0,"trace_depth_exceeded":0,"trace_dropped":0,"trace_capped":false,"trace_nonmonotonic_pairs":0,"trace_rejected_unknown_api":0,"ring_loss":[0,0,0,0,0,0,0,0],"class_window":null,"pairing_uncertain":true,"pairing_uncertainty":["decode-reject"],"unmeasured_seqs":[],"gaps":[],"gap_overflow":0,"exemplars":[]},"pairing_uncertain":true,"class_epoch":null}}"#;
        assert_eq!(check_trace_summary_raw_duplicates(text), Ok(()));
        // Doubled by_api identity convicts.
        let at = text.find(r#""20":{"#).unwrap();
        let mut dup2 = text.to_string();
        dup2.insert_str(
            at,
            r#""20":{"success":{"buckets":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"sum":5,"count":1}},"#,
        );
        let err = check_trace_summary_raw_duplicates(&dup2)
            .expect_err("a doubled by_api key must not pass");
        assert!(err.contains("duplicate field"), "{err}");
        assert!(!err.contains("`20`"), "key must not echo: {err}");
        // The collapsed Value path is blind (premise of the check).
        let collapsed: serde_json::Value = serde_json::from_str(&dup2).unwrap();
        assert!(collapsed["trace_summary"]["by_api"]["20"].is_object());
        // Envelope shape (document.trace_summary) convicts too.
        let env = format!(r#"{{"seq":0,"generation":1,"document":{text}}}"#);
        assert_eq!(check_trace_summary_raw_duplicates(&env), Ok(()));
        let env_dup = env.replacen(
            r#""20":{"#,
            r#""20":{"success":{"buckets":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],"sum":0,"count":0}},"20":{"#,
            1,
        );
        let err =
            check_trace_summary_raw_duplicates(&env_dup).expect_err("envelope dup must not pass");
        assert!(err.contains("duplicate field"), "{err}");
        assert!(!err.contains("`20`"), "key must not echo: {err}");
        // A repeated SECTION member rejects (it conceals the
        // checked one under last-wins).
        let mut outside = text.to_string();
        let end = outside.rfind('}').unwrap();
        outside.insert_str(end, r#","trace_summary":{"version":1}"#);
        assert!(check_trace_summary_raw_duplicates(&outside).is_err());
        // Duplicates OUTSIDE the section keep last-wins.
        let clean = r#"{"a":1,"a":2,"trace_summary":{"version":1}}"#;
        assert_eq!(check_trace_summary_raw_duplicates(clean), Ok(()));
    }

    #[test]
    fn api_activity_raw_duplicates_reject() {
        // P2fix7 NEW-42: duplicate keys under `api_activity` (a
        // doubled row member, a doubled nested gaps member)
        // reject on the RAW text — the collapsed `Value` path is
        // blind (last-wins). Both text shapes covered: document
        // text + envelope bytes.
        let text = r#"{"api_activity":[{"api":20,"entries":1,"gaps":{"map":0,"depth":0}}]}"#;
        assert_eq!(check_api_activity_raw_duplicates(text), Ok(()));
        // Doubled row member convicts.
        let rowdup = text.replacen(r#"{"api":20,"#, r#"{"api":99,"api":20,"#, 1);
        let err = check_api_activity_raw_duplicates(&rowdup)
            .expect_err("a doubled row member must not pass");
        assert!(err.contains("duplicate field"), "{err}");
        // Doubled nested gaps member convicts.
        let gapsdup = text.replacen(r#"{"map":0,"#, r#"{"map":7,"map":0,"#, 1);
        let err = check_api_activity_raw_duplicates(&gapsdup)
            .expect_err("a doubled gaps member must not pass");
        assert!(err.contains("duplicate field"), "{err}");
        // The collapsed Value path is blind (premise of the check).
        let collapsed: serde_json::Value = serde_json::from_str(&rowdup).unwrap();
        assert_eq!(collapsed["api_activity"][0]["api"], serde_json::json!(20));
        // Envelope shape (document.api_activity) convicts too.
        let env = format!(r#"{{"seq":0,"generation":1,"document":{text}}}"#);
        assert_eq!(check_api_activity_raw_duplicates(&env), Ok(()));
        let env_dup = env.replacen(r#"{"api":20,"#, r#"{"api":99,"api":20,"#, 1);
        let err =
            check_api_activity_raw_duplicates(&env_dup).expect_err("envelope dup must not pass");
        assert!(err.contains("duplicate field"), "{err}");
        // A repeated SECTION member rejects (it conceals the
        // checked one under last-wins).
        let mut outside = text.to_string();
        let end = outside.rfind('}').unwrap();
        outside.insert_str(end, r#","api_activity":[]"#);
        assert!(check_api_activity_raw_duplicates(&outside).is_err());
        // Duplicates OUTSIDE the section keep last-wins.
        let clean = r#"{"a":1,"a":2,"api_activity":[{"api":20}]}"#;
        assert_eq!(check_api_activity_raw_duplicates(clean), Ok(()));
    }

    // NEW-33 fix9 pin (host, raw document intake): the document gate
    // receives a `Value` AFTER duplicate keys have collapsed, so raw
    // duplicates in `request_evidence` (notably a doubled
    // `start_ns`/`end_ns`) are invisible to it. The raw-text intake
    // validates the RAW section before normalization and rejects
    // duplicates with duplicate-field errors for BOTH keys — using
    // otherwise-valid replacements (the same values), so only
    // duplicate detection can convict. Duplicates OUTSIDE the
    // section keep last-wins (out of scope).
    #[test]
    fn raw_intake_rejects_duplicate_section_keys_before_normalization() {
        use crate::provider_observation::request_evidence::{
            FETCH_SURFACES, RequestEvidence, RequestScope,
        };
        // A fully valid v2.8 document WITH a published silence
        // interval (windowed fold + matching activity sum).
        let evidence = RequestEvidence::fold(
            &[],
            RequestScope {
                operational_entries: Some(7),
                fetch_armed: FETCH_SURFACES.iter().map(|s| s.id).collect(),
                window: Some((100, 200)),
                silence_start: Some(150),
                silence_end: None,
                fence_cuts: Vec::new(),
            },
        );
        let silence = evidence.silence_window.expect("the fold publishes");
        assert_eq!((silence.start_ns, silence.end_ns), (150, 200));
        let mut doc = crate::capture::empty_document();
        doc.window.requested_start_ns = 100;
        doc.window.requested_end_ns = 200;
        doc.window.effective_start_ns = 100;
        doc.window.effective_end_ns = 200;
        doc.api_activity = crate::api_activity::merge(vec![crate::api_activity::ApiActivityRow {
            api: crate::api_activity::ApiId::try_from(20).unwrap(),
            entries: 7,
            observed_success: 7,
            observed_failure: 0,
            verification_mismatch: 0,
            unsupported: 0,
            gaps: crate::api_activity::ApiActivityGaps::default(),
        }])
        .expect("rows merge");
        crate::evidence::stamp_request_evidence(&mut doc, evidence.clone());
        let rendered = crate::report::render_json(&doc).expect("render");
        let valid = std::str::from_utf8(&rendered).expect("utf8").to_owned();
        assert_eq!(
            check_v2_document_text(&valid),
            Ok(()),
            "premise: the valid document clears the full raw intake"
        );
        // Splice duplicates into the flat silence object (the
        // render is pretty-printed; the first `}` after its start
        // still closes it) — otherwise-valid values (the same
        // start/end), so a collapsed read stays valid and ONLY
        // duplicate detection rejects.
        let key = "\"silence_window\": {";
        let at = valid
            .find(key)
            .expect("premise: the rendered doc carries its silence object")
            + key.len();
        let rel = valid[at..]
            .find('}')
            .expect("premise: the flat silence object closes");
        let mut dup_start = valid.clone();
        dup_start.insert_str(at + rel, ",\"start_ns\":150");
        let mut dup_end = valid.clone();
        dup_end.insert_str(at + rel, ",\"end_ns\":200");
        // The finding's premise: the collapsed `Value` path is blind
        // (last-wins yields the valid document — both gates accept).
        for (name, dup) in [("start", dup_start.clone()), ("end", dup_end.clone())] {
            let collapsed: serde_json::Value =
                serde_json::from_str(&dup).expect("the dup text parses to a Value");
            assert!(
                validate_v2(&collapsed).is_ok() && check_v2_semantics(&collapsed).is_ok(),
                "premise: the Value gate accepts the collapsed {name}-dup document"
            );
        }
        // The raw scan convicts BOTH keys with duplicate-field errors.
        let err = check_request_evidence_raw_duplicates(&dup_start)
            .expect_err("a duplicated start_ns must not pass the raw section check");
        assert!(
            err.contains("duplicate field"),
            "the start error is a duplicate-field error: {err}"
        );
        assert!(!err.contains("start_ns"), "key must not echo: {err}");
        let err = check_request_evidence_raw_duplicates(&dup_end)
            .expect_err("a duplicated end_ns must not pass the raw section check");
        assert!(
            err.contains("duplicate field"),
            "the end error is a duplicate-field error: {err}"
        );
        assert!(!err.contains("end_ns"), "key must not echo: {err}");
        // A nested in-section duplicate convicts the same way.
        let ops_at = valid
            .find("\"ops\": 7")
            .expect("premise: the remainder renders its ops");
        let mut dup_ops = valid.clone();
        dup_ops.insert_str(ops_at + "\"ops\": 7".len(), ",\"ops\":7");
        let err = check_request_evidence_raw_duplicates(&dup_ops)
            .expect_err("a nested in-section duplicate must not pass");
        assert!(
            err.contains("duplicate field"),
            "the nested error is a duplicate-field error: {err}"
        );
        assert!(!err.contains("`ops`"), "key must not echo: {err}");
        // Scope control: a duplicate OUTSIDE the section keeps
        // last-wins (the raw check ignores it).
        let root_end = valid.rfind('}').expect("premise: the doc closes");
        let mut outside = valid.clone();
        outside.insert_str(root_end, ",\"schema_version\":\"observed-crypto-v2.8\"");
        assert_eq!(
            check_request_evidence_raw_duplicates(&outside),
            Ok(()),
            "a duplicate outside the section is out of scope"
        );
        // The full intake rejects the raw dups before normalization.
        for (name, dup) in [("start", dup_start), ("end", dup_end)] {
            let err = check_v2_document_text(&dup)
                .expect_err("the full intake must reject the raw {name}-dup document");
            assert!(
                err.contains("duplicate field"),
                "the intake {name} error is a duplicate-field error: {err}"
            );
            assert!(
                !err.contains(&format!("`{name}_ns`")),
                "key must not echo: {err}"
            );
        }
        // NEW-33-OPEN fix10: a REPEATED top-level section is
        // rejected before normalization — the raw scan used to
        // walk only the FIRST member while `Value` parsing
        // last-wins, so a duplicate-bearing second member replaced
        // the checked one and concealed its nested duplicates.
        // Splice a second top-level `request_evidence` member
        // (clean, and duplicate-bearing) after the first.
        let section = serde_json::to_string(&evidence).expect("section serializes");
        let skey = "\"silence_window\":{";
        let sat = section
            .find(skey)
            .expect("premise: the section carries its silence object")
            + skey.len();
        let srel = section[sat..]
            .find('}')
            .expect("premise: the flat silence object closes");
        let mut section_dup = section.clone();
        section_dup.insert_str(sat + srel, ",\"start_ns\":150");
        let root_end = valid.rfind('}').expect("premise: the doc closes");
        for (name, second) in [
            ("clean-second", section.clone()),
            ("dup-second", section_dup.clone()),
        ] {
            let mut two = valid.clone();
            two.insert_str(root_end, &format!(",\"request_evidence\":{second}"));
            // The finding's premise: the collapsed `Value` path is
            // blind (last-wins yields a valid document — both gates
            // accept, the second member's nested dup concealed).
            let collapsed: serde_json::Value =
                serde_json::from_str(&two).expect("the two-section text parses to a Value");
            assert!(
                validate_v2(&collapsed).is_ok() && check_v2_semantics(&collapsed).is_ok(),
                "premise: the Value gate accepts the collapsed {name} document"
            );
            let err = check_request_evidence_raw_duplicates(&two)
                .expect_err("a repeated top-level section must not pass the raw check");
            assert!(
                err.contains("duplicate field `request_evidence`"),
                "the raw {name} error names the repeated section: {err}"
            );
            let err = check_v2_document_text(&two)
                .expect_err("the full intake must reject the repeated-section document");
            assert!(
                err.contains("duplicate field `request_evidence`"),
                "the intake {name} error names the repeated section: {err}"
            );
        }
    }

    #[test]
    fn compat_matrix_v2() {
        assert!(check_version_v2("observed-crypto-v2.0"));
        assert!(check_version_v2("observed-crypto-v2.9"));
        assert!(check_version_v2("observed-crypto-v2"));
        // P2fix10 NEW-62: the representable minor domain is u64 —
        // the upper boundary admits, overflow rejects.
        assert!(check_version_v2("observed-crypto-v2.18446744073709551615"));
        assert!(!check_version_v2("observed-crypto-v2.18446744073709551616"));
        assert!(!check_version_v2("observed-crypto-v1.0"));
        assert!(!check_version_v2("observed-crypto-v1"));
        assert!(!check_version_v2("observed-crypto-v3.0"));
        assert!(!check_version_v2("observed-crypto-v0.9"));
        assert!(!check_version_v2("0.2-provisional"));
        assert!(!check_version_v2(""));
        assert!(!check_version_v2("observed-crypto-v2.x"));
        assert!(!check_version_v2("observed-crypto-vX"));
        assert!(!check_version_v2("2.0"));
        // Cross-major rejection both ways (old readers refuse v2).
        assert!(!check_version("observed-crypto-v2.0"));
        assert!(!check_version_v2("observed-crypto-v1.0"));
    }

    /// Validate `doc` against an inline schema (validator keyword
    /// semantics, independent of the v2 schema file).
    fn check_inline(
        schema: &serde_json::Value,
        doc: &serde_json::Value,
    ) -> Result<(), SchemaError> {
        validate_against(schema, doc, schema, "$", 0)
    }

    #[test]
    fn validator_type_matrix() {
        use serde_json::json;
        let schema = json!({"type": "integer"});
        assert!(check_inline(&schema, &json!(5)).is_ok());
        assert!(check_inline(&schema, &json!(-5)).is_ok());
        assert!(
            check_inline(&schema, &json!(5.0)).is_ok(),
            "1.0 is an integer"
        );
        assert!(check_inline(&schema, &json!(5.5)).is_err());
        assert!(check_inline(&schema, &json!("5")).is_err());
        let schema = json!({"type": ["integer", "null"]});
        assert!(check_inline(&schema, &json!(5)).is_ok());
        assert!(check_inline(&schema, &json!(null)).is_ok());
        assert!(check_inline(&schema, &json!("5")).is_err());
        let schema = json!({"type": "number"});
        assert!(check_inline(&schema, &json!(5.5)).is_ok());
        assert!(check_inline(&schema, &json!(5)).is_ok());
        for (name, doc) in [
            ("null", json!(null)),
            ("boolean", json!(true)),
            ("object", json!({})),
            ("array", json!([])),
            ("string", json!("x")),
        ] {
            let schema = json!({"type": name});
            assert!(check_inline(&schema, &doc).is_ok(), "{name} accepts");
        }
        let schema = json!({"type": "bogus"});
        assert!(
            check_inline(&schema, &json!(1)).is_err(),
            "unknown type fails"
        );
    }

    #[test]
    fn validator_pattern_single_shipped_shape() {
        // P2fix6 NEW-37: `pattern` evaluates the single shipped
        // shape (canonical lowercase 16-hex) by its exact manual
        // equivalent — lowercase accepts, uppercase/short/long/
        // non-hex reject — and any other pattern fails closed
        // (no regex engine ships).
        use serde_json::json;
        let schema = json!({"type": "string", "pattern": "^[0-9a-f]{16}$"});
        assert!(check_inline(&schema, &json!("814dd7b9784d57c1")).is_ok());
        for bad in [
            "814DD7B9784D57C1",
            "814dd7b9784d57c",
            "814dd7b9784d57c12",
            "814dd7b9784d57c!",
            "",
        ] {
            assert!(
                check_inline(&schema, &json!(bad)).is_err(),
                "{bad:?} must not match"
            );
        }
        let other = json!({"type": "string", "pattern": "^a+$"});
        assert!(
            check_inline(&other, &json!("aaa")).is_err(),
            "an unevaluatable pattern fails closed"
        );
    }

    #[test]
    fn validator_enum_const() {
        use serde_json::json;
        let schema = json!({"enum": ["a", "b"]});
        assert!(check_inline(&schema, &json!("a")).is_ok());
        assert!(check_inline(&schema, &json!("c")).is_err());
        let schema = json!({"const": true});
        assert!(check_inline(&schema, &json!(true)).is_ok());
        assert!(check_inline(&schema, &json!(false)).is_err());
        assert!(check_inline(&schema, &json!(1)).is_err());
    }

    #[test]
    fn validator_object_keywords() {
        use serde_json::json;
        let schema = json!({
            "type": "object",
            "required": ["a"],
            "properties": {"a": {"type": "integer"}},
            "additionalProperties": false,
        });
        assert!(check_inline(&schema, &json!({"a": 1})).is_ok());
        assert!(
            check_inline(&schema, &json!({})).is_err(),
            "missing required"
        );
        assert!(
            check_inline(&schema, &json!({"a": "x"})).is_err(),
            "wrong type"
        );
        assert!(
            check_inline(&schema, &json!({"a": 1, "b": 2})).is_err(),
            "additionalProperties: false rejects"
        );
        // additionalProperties as schema applies to undeclared keys.
        let schema = json!({
            "type": "object",
            "properties": {"a": true},
            "additionalProperties": {"type": "string"},
        });
        assert!(check_inline(&schema, &json!({"a": 1, "b": "x"})).is_ok());
        assert!(check_inline(&schema, &json!({"b": 1})).is_err());
        // Boolean schemas: true accepts, false rejects.
        assert!(check_inline(&json!(true), &json!([1, {"x": 1}])).is_ok());
        assert!(check_inline(&json!(false), &json!(null)).is_err());
    }

    #[test]
    fn validator_ignores_mismatched_type_keywords() {
        // Specification behavior: `required`/`properties`/`minimum`
        // and friends assert only on matching types and are ignored
        // otherwise; enforcement comes from combining them with
        // `type`. A validator that errors here is not JSON Schema.
        use serde_json::json;
        let schema = json!({"required": ["a"], "minimum": 3});
        assert!(check_inline(&schema, &json!("nope")).is_ok());
        assert!(check_inline(&schema, &json!([1])).is_ok());
        let schema = json!({"properties": {"a": false}, "items": false});
        assert!(check_inline(&schema, &json!("nope")).is_ok());
        assert!(check_inline(&schema, &json!(7)).is_ok());
    }

    #[test]
    fn validator_array_string_bounds() {
        use serde_json::json;
        let schema = json!({"type": "array", "items": {"type": "integer"}});
        assert!(check_inline(&schema, &json!([1, 2])).is_ok());
        assert!(check_inline(&schema, &json!([1, "x"])).is_err());
        let schema = json!({"type": "array", "minItems": 1, "maxItems": 2});
        assert!(check_inline(&schema, &json!([])).is_err());
        assert!(check_inline(&schema, &json!([1, 2, 3])).is_err());
        assert!(check_inline(&schema, &json!([1])).is_ok());
        let schema = json!({"type": "string", "minLength": 1, "maxLength": 2});
        assert!(check_inline(&schema, &json!("")).is_err());
        assert!(check_inline(&schema, &json!("abc")).is_err());
        assert!(check_inline(&schema, &json!("ab")).is_ok());
    }

    #[test]
    fn validator_numeric_bounds_are_exact() {
        use serde_json::json;
        let schema: serde_json::Value = serde_json::from_str(
            r#"{"type": "integer", "minimum": 0, "maximum": 18446744073709551615}"#,
        )
        .unwrap();
        assert!(check_inline(&schema, &json!(0)).is_ok());
        let max: serde_json::Value = serde_json::from_str("18446744073709551615").unwrap();
        assert!(check_inline(&schema, &max).is_ok(), "u64::MAX accepted");
        assert!(
            check_inline(&schema, &json!(-1)).is_err(),
            "negative rejected"
        );
        // 2^64 parses as f64 (serde_json falls back past u64); it is
        // integral so `integer` accepts, but the maximum rejects —
        // naive f64 comparison would round u64::MAX up to 2^64 and
        // wrongly accept.
        let over: serde_json::Value = serde_json::from_str("18446744073709551616").unwrap();
        assert!(over.is_f64(), "2^64 parses as float");
        assert!(check_inline(&schema, &over).is_err(), "2^64 rejected");
        let schema: serde_json::Value =
            serde_json::from_str(r#"{"minimum": -2147483648, "maximum": 2147483647}"#).unwrap();
        let lo: serde_json::Value = serde_json::from_str("-2147483648").unwrap();
        let under: serde_json::Value = serde_json::from_str("-2147483649").unwrap();
        assert!(check_inline(&schema, &lo).is_ok());
        assert!(check_inline(&schema, &under).is_err());
    }

    #[test]
    fn validator_combinators() {
        use serde_json::json;
        let schema = json!({"anyOf": [{"type": "string"}, {"type": "integer"}]});
        assert!(check_inline(&schema, &json!("x")).is_ok());
        assert!(check_inline(&schema, &json!(1)).is_ok());
        assert!(check_inline(&schema, &json!(null)).is_err());
        let schema = json!({"allOf": [{"type": "integer"}, {"minimum": 3}]});
        assert!(check_inline(&schema, &json!(4)).is_ok());
        assert!(check_inline(&schema, &json!(2)).is_err());
        let schema = json!({"oneOf": [{"type": "integer"}, {"minimum": 3}]});
        assert!(
            check_inline(&schema, &json!(2)).is_ok(),
            "exactly one branch"
        );
        assert!(
            check_inline(&schema, &json!(4)).is_err(),
            "two branches match"
        );
    }

    #[test]
    fn validator_refs() {
        use serde_json::json;
        let schema = json!({
            "$defs": {"count": {"type": "integer", "minimum": 0}},
            "type": "object",
            "properties": {"n": {"$ref": "#/$defs/count"}},
            "additionalProperties": false,
        });
        assert!(check_inline(&schema, &json!({"n": 2})).is_ok());
        assert!(check_inline(&schema, &json!({"n": -1})).is_err());
        assert!(check_inline(&schema, &json!({"n": "x"})).is_err());
        // Sibling keywords apply alongside $ref (2020-12).
        let schema = json!({
            "$defs": {"any": true},
            "$ref": "#/$defs/any",
            "type": "string",
        });
        assert!(check_inline(&schema, &json!("x")).is_ok());
        assert!(check_inline(&schema, &json!(1)).is_err());
        // Dangling, remote and malformed refs fail closed.
        let schema = json!({"$ref": "#/$defs/missing"});
        assert!(check_inline(&schema, &json!(1)).is_err());
        let schema = json!({"$ref": "https://example.com/schema"});
        assert!(check_inline(&schema, &json!(1)).is_err());
        // Self-reference terminates via the depth guard.
        let schema = json!({"$ref": "#"});
        assert!(check_inline(&schema, &json!(1)).is_err());
    }

    #[test]
    fn validator_unsupported_keywords_fail_closed() {
        use serde_json::json;
        for schema in [
            json!({"type": "string", "pattern": "^a+$"}),
            json!({"type": "string", "format": "date-time"}),
            json!({"prefixItems": [{"type": "integer"}]}),
            json!({"if": {"type": "string"}}),
        ] {
            assert!(
                check_inline(&schema, &json!("aaa")).is_err(),
                "unsupported keyword must fail closed: {schema}"
            );
        }
    }

    #[test]
    fn semantics_fails_closed_on_malformed_shape() {
        // Missing sections are errors, never panics (the semantic
        // layer never assumes schema validation ran first).
        use serde_json::json;
        for doc in [
            json!({}),
            json!([]),
            json!({"schema_version": "observed-crypto-v2.0"}),
            json!({"schema_version": "observed-crypto-v2.0", "sites": {}}),
        ] {
            assert!(check_v2_semantics(&doc).is_err(), "accepted {doc}");
        }
        assert!(check_v2_semantics(&json!(null)).is_err());
    }

    #[test]
    fn v2_traversal_section_accepts_emitter_shapes() {
        // I4/K3: the shipped schema accepts the full traversal
        // section the emitter produces (all ten keys, every
        // outcome/true_t/reason/abandon variant shape) and rejects
        // malformed ones (unknown keys, short sha256, wrong
        // variant envelopes).
        use serde_json::json;
        let schema: serde_json::Value = serde_json::from_str(V2_SCHEMA_JSON).unwrap();
        let node = schema["properties"]["traversal"].clone();
        let check = |v: &serde_json::Value| validate_against(&node, v, &schema, "$", 0);
        let obj = |sha: &str| json!({"path": "/lib/osslscope/osslscope-harvest", "sha256": sha});
        let sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        let good = json!({
            "harvest": obj(sha),
            "count": obj(sha),
            "members": obj(sha),
            "records": 14,
            "findings": 1,
            "polls": 3,
            "admitted": {"7": 10, "12": 4},
            "entries": [
                {"tid": 7, "seq": 0, "op": 7,
                 "outcome": {"Complete": {"true_t": 6, "cached": false}},
                 "true_t": {"Proven": 6}, "alg_count": 7, "row_count": 3,
                 "generation": 9},
                {"tid": 7, "seq": 1, "op": 12,
                 "outcome": {"Partial": {"reasons": [
                     {"Holes": [3]}, {"Unreadable": [4]}, {"Trunc": 6},
                     {"UnobservedSlots": [9]},
                     {"CacheShrink": {"cached": 9, "observed": 4}},
                     {"CacheStale": {"cached": 9}},
                     {"GenStale": {"expected": 1, "observed": 2}},
                     "GuardError", "Overfull", "DrainLoss", "GuardMissing",
                     "GenMixed", "DanglingCall", "TerminatorUnproven",
                     "RowArrayMismatch", "FaultViewUncertain"
                 ]}},
                 "true_t": {"Candidate": 4}, "alg_count": 5, "row_count": 0,
                 "generation": null},
                {"tid": 8, "seq": 0, "op": 7,
                 "outcome": {"Skipped": {"cause": 1}},
                 "true_t": "EmptyTable", "alg_count": 0, "row_count": 0,
                 "generation": null},
                {"tid": 8, "seq": 1, "op": 7,
                 "outcome": {"Tainted": {"by_seq": 3}},
                 "true_t": "Unknown", "alg_count": 1, "row_count": 0,
                 "generation": 2},
                {"tid": 9, "seq": 0, "op": 7,
                 "outcome": {"Abandoned": {"reason": "Hung"}},
                 "true_t": {"Proven": 1}, "alg_count": 0, "row_count": 0,
                 "generation": null}
            ],
            "admitted_unknown": [9],
            "census_loss": 2
        });
        check(&good).expect("emitter traversal shape validates");
        // Every abandon reason spelling validates.
        for reason in [
            "SkipVictim",
            "Churned",
            "Evicted",
            "RetireFailed",
            "StaleRepaired",
            "Stalled",
            "Detached",
            "PreWindow",
            "Hung",
        ] {
            let mut v = good.clone();
            v["entries"][4]["outcome"] = json!({"Abandoned": {"reason": reason}});
            check(&v).expect(format!("abandon reason {reason} validates").as_str());
        }
        // Malformed shapes reject.
        let mut unknown_key = good.clone();
        unknown_key["entries"][0]["bogus"] = json!(1);
        assert!(check(&unknown_key).is_err(), "unknown entry key rejects");
        let mut short_sha = good.clone();
        short_sha["harvest"]["sha256"] = json!("abc");
        assert!(check(&short_sha).is_err(), "short sha256 rejects");
        let mut bad_outcome = good.clone();
        bad_outcome["entries"][0]["outcome"] = json!({"Complete": {"true_t": 6}});
        assert!(check(&bad_outcome).is_err(), "short Complete rejects");
        let mut bad_reason = good.clone();
        bad_reason["entries"][1]["outcome"]["Partial"]["reasons"] = json!(["Nope"]);
        assert!(check(&bad_reason).is_err(), "unknown reason rejects");
        let mut bad_gen = good.clone();
        bad_gen["entries"][0]["generation"] = json!("9");
        assert!(check(&bad_gen).is_err(), "string generation rejects");
    }

    #[test]
    fn v2_schema_uses_only_supported_keywords() {
        // The shipped v2 schema must load under the validator: any
        // future keyword addition fails here until validator support
        // lands with it.
        let schema: serde_json::Value = serde_json::from_str(V2_SCHEMA_JSON).unwrap();
        let empty = serde_json::json!({});
        let Err(e) = check_inline(&schema, &empty) else {
            panic!("empty doc validates — schema lost its required keys?");
        };
        assert!(
            !e.message.contains("unsupported schema keyword"),
            "v2 schema uses an unsupported keyword: {e}"
        );
    }

    #[test]
    fn r12_old_strict_schema_rejects_context_key() {
        // A strict validator pinned to the pre-R12 schema rejects a
        // context-bearing document (top-level additionalProperties)
        // — EXPECTED: strict validators upgrade with the schema,
        // while field readers ignore unknown keys (see
        // output_contract r12_old_reader_ignores_context).
        let dir = format!("{}/tests/goldens", env!("CARGO_MANIFEST_DIR"));
        let doc: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(format!("{dir}/report-v2-complete.json")).unwrap(),
        )
        .unwrap();
        assert!(
            doc.get("context").is_some(),
            "golden must carry context for the old-strict pin"
        );
        validate_v2(&doc).expect("new schema accepts context");
        let mut old_schema: serde_json::Value = serde_json::from_str(V2_SCHEMA_JSON).unwrap();
        old_schema
            .get_mut("properties")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("context");
        let Err(e) = check_inline(&old_schema, &doc) else {
            panic!("old strict schema accepted a context-bearing doc");
        };
        assert_eq!(e.path, "$.context");
        assert_eq!(e.message, "value forbidden here");
    }

    #[test]
    fn r12_new_reader_accepts_context_free_older_minor() {
        // Mirror of r12_old_strict_schema_rejects_context_key: the
        // additive direction. A pre-R12 document (no `context` key)
        // validates under the current schema and semantics — old
        // documents stay readable, only old STRICT validators refuse
        // new keys.
        let dir = format!("{}/tests/goldens", env!("CARGO_MANIFEST_DIR"));
        let mut doc: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(format!("{dir}/report-v2-complete.json")).unwrap(),
        )
        .unwrap();
        assert!(doc.get("context").is_some(), "golden must carry context");
        doc.as_object_mut().unwrap().remove("context");
        validate_v2(&doc).expect("new schema accepts context-free doc");
        check_v2_semantics(&doc).expect("new semantics accept context-free doc");
    }

    #[test]
    fn v26_gate_sysctls_need_minor_6_and_coarse_domain_above() {
        // T5 schema D-record rules 1/5/9: sysctls sections need
        // minor >= 6; at minor >= 6 openssl.version must be null or
        // coarse; earlier minors keep free strings.
        let dir = format!("{}/tests/goldens", env!("CARGO_MANIFEST_DIR"));
        let golden: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(format!("{dir}/report-v2-complete.json")).unwrap(),
        )
        .unwrap();
        let with_sysctls = |mut doc: serde_json::Value| {
            doc["context"]["sysctls"] = serde_json::json!({
                "perf_event_paranoid": 4,
                "kptr_restrict": 1,
                "unprivileged_bpf_disabled": 2,
                "ptrace_scope": 0,
            });
            doc
        };
        // 2.4 + sysctls → gate rejects (minor too low).
        let v24 = with_sysctls(golden.clone());
        assert_eq!(v24["schema_version"], "observed-crypto-v2.4");
        let err = check_v2_semantics(&v24).unwrap_err();
        assert!(err.contains("minor >= 6"), "got: {err}");
        // 2.6 + sysctls + coarse → gate passes (full semantics may
        // still fail elsewhere; assert NOT the gate error).
        let mut v26 = with_sysctls(golden.clone());
        v26["schema_version"] = serde_json::Value::from("observed-crypto-v2.6");
        v26["openssl"]["version"] = serde_json::Value::from("3.5");
        match check_v2_semantics(&v26) {
            Ok(()) => {}
            Err(err) => assert!(
                !err.contains("minor >= 6") && !err.contains("coarse family"),
                "gate must pass, got: {err}"
            ),
        }
        // 2.6 + patch string → coarse-domain rejects.
        let mut v26patch = with_sysctls(golden.clone());
        v26patch["schema_version"] = serde_json::Value::from("observed-crypto-v2.6");
        v26patch["openssl"]["version"] = serde_json::Value::from("3.5.1");
        let err = check_v2_semantics(&v26patch).unwrap_err();
        assert!(err.contains("coarse family"), "got: {err}");
        // 2.4 + patch string → gate passes (historical domain kept).
        let mut v24patch = golden.clone();
        v24patch["openssl"]["version"] = serde_json::Value::from("3.5.1");
        match check_v2_semantics(&v24patch) {
            Ok(()) => {}
            Err(err) => assert!(
                !err.contains("minor >= 6") && !err.contains("coarse family"),
                "old minor keeps free strings, got: {err}"
            ),
        }
    }

    #[test]
    fn t5_cell6_r12_mirrors_sysctls_and_historical_patch_strings() {
        // T5 schema D-record rule 9: old STRICT validators refuse
        // the new sysctls KEY (naming it), never minor 2.6 itself;
        // UNCHANGED historical 2.4/2.5 patch-string fixtures keep
        // validating under the new schema AND semantics.
        let dir = format!("{}/tests/goldens", env!("CARGO_MANIFEST_DIR"));
        let v26: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(format!("{dir}/report-v2_6-sysctls.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(v26["schema_version"], "observed-crypto-v2.6");
        validate_v2(&v26).expect("new schema accepts 2.6 doc");
        check_v2_semantics(&v26).expect("new semantics accept 2.6 doc");
        let mut old_schema: serde_json::Value = serde_json::from_str(V2_SCHEMA_JSON).unwrap();
        old_schema
            .get_mut("properties")
            .unwrap()
            .get_mut("context")
            .unwrap()
            .get_mut("properties")
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove("sysctls");
        let Err(e) = check_inline(&old_schema, &v26) else {
            panic!("pinned pre-2.6 strict schema accepted a sysctls-bearing doc");
        };
        assert!(
            e.path.contains("sysctls"),
            "refusal names the key, got: {} ({})",
            e.path,
            e.message
        );
        // Historical fixtures stay patch-shaped AND valid.
        for (name, minor) in [
            ("report-v2-complete.json", "observed-crypto-v2.4"),
            ("report-v2_5-execution.json", "observed-crypto-v2.5"),
        ] {
            let doc: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(format!("{dir}/{name}")).unwrap())
                    .unwrap();
            assert_eq!(doc["schema_version"], minor);
            let version = doc["openssl"]["version"].as_str().unwrap();
            assert!(
                version.matches('.').count() >= 2,
                "{name} must stay patch-shaped, got {version:?}"
            );
            validate_v2(&doc).expect("{name} validates under the new schema");
            check_v2_semantics(&doc).expect("{name} passes the new semantics");
        }
    }

    #[test]
    fn forbidden_keys_rejected_at_both_layers() {
        // Secret-canary positive control for the reader gate: every
        // key in FORBIDDEN_V2_KEYS (raw argv/cmdline/env/addresses)
        // is rejected structurally by validate_v2 AND named by the
        // check_v2_semantics sweep — at top level and nested.
        let dir = format!("{}/tests/goldens", env!("CARGO_MANIFEST_DIR"));
        let golden: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(format!("{dir}/report-v2-complete.json")).unwrap(),
        )
        .unwrap();
        for key in FORBIDDEN_V2_KEYS {
            let mut top = golden.clone();
            top.as_object_mut().unwrap().insert(
                (*key).to_string(),
                serde_json::Value::from("canary-tripwire"),
            );
            assert!(
                validate_v2(&top).is_err(),
                "schema must reject top-level {key:?}"
            );
            let Err(err) = check_v2_semantics(&top) else {
                panic!("sweep must reject top-level {key:?}");
            };
            assert!(err.contains(key), "sweep names the key, got: {err}");
            let mut nested = golden.clone();
            nested["target"]
                .as_object_mut()
                .unwrap()
                .insert((*key).to_string(), serde_json::Value::from(1));
            let Err(err) = check_v2_semantics(&nested) else {
                panic!("sweep must reject nested {key:?}");
            };
            assert!(err.contains(key), "nested sweep names the key, got: {err}");
        }
    }

    fn report_golden_names(names: impl Iterator<Item = String>) -> Vec<String> {
        let mut names: Vec<_> = names
            .filter(|f| f.starts_with("report-") && f.ends_with(".json"))
            .collect();
        names.sort();
        names
    }

    fn report_goldens() -> Vec<(String, serde_json::Value)> {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/goldens");
        let names = report_golden_names(
            std::fs::read_dir(&dir)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap()),
        );
        assert!(
            names.len() >= 5,
            "expected report goldens, found {}",
            names.len()
        );
        names
            .into_iter()
            .map(|name| {
                let text = std::fs::read_to_string(dir.join(&name))
                    .unwrap_or_else(|e| panic!("{name}: read: {e}"));
                let doc =
                    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name}: JSON: {e}"));
                (name, doc)
            })
            .collect()
    }

    fn validate_report_golden(name: &str, doc: &serde_json::Value) -> Result<(), String> {
        let version = doc
            .get("schema_version")
            .and_then(|v| v.as_str())
            .ok_or_else(|| format!("{name}: schema_version must be a string"))?;
        if !check_version_v2(version) || check_version(version) {
            return Err(format!("{name}: live report requires v2, got {version:?}"));
        }
        validate_v2(doc).map_err(|e| format!("{name}: schema: {e}"))?;
        check_v2_semantics(doc).map_err(|e| format!("{name}: semantics: {e}"))
    }

    fn execution_golden() -> serde_json::Value {
        serde_json::from_str(include_str!("../tests/goldens/report-v2_5-execution.json")).unwrap()
    }

    #[test]
    fn report_golden_enumeration_includes_all_version_names() {
        // A filename may neither hide a document from validation nor declare its version.
        let names = report_golden_names(
            [
                "report-v2_5-execution.json",
                "other.json",
                "report-v1-old.json",
                "report-neutral.json",
                "report-v2-complete.json",
                "report-v2.json.bak",
            ]
            .into_iter()
            .map(str::to_owned),
        );
        assert_eq!(
            names,
            [
                "report-neutral.json",
                "report-v1-old.json",
                "report-v2-complete.json",
                "report-v2_5-execution.json",
            ]
        );
    }

    #[test]
    fn report_golden_version_comes_from_document() {
        use serde_json::json;
        let good = execution_golden();
        for name in [
            "report-v2_5-execution.json",
            "report-v2-complete.json",
            "report-v1-misleading.json",
        ] {
            validate_report_golden(name, &good).unwrap();
        }
        for version in [
            json!(null),
            json!(2),
            json!("observed-crypto-v1"),
            json!("observed-crypto-v1.9"),
            json!("observed-crypto-v3.0"),
            json!("observed-crypto-v2.x"),
            json!("observed-crypto-v2."),
            json!(""),
        ] {
            let mut doc = good.clone();
            doc["schema_version"] = version;
            let error = validate_report_golden("report-v2-misleading.json", &doc).unwrap_err();
            assert!(error.starts_with("report-v2-misleading.json:"), "{error}");
        }
        let mut missing = good;
        missing.as_object_mut().unwrap().remove("schema_version");
        assert!(validate_report_golden("report-v2-missing.json", &missing).is_err());
    }

    #[test]
    fn report_golden_validation_keeps_schema_and_attribution_strict() {
        use serde_json::json;
        let good = execution_golden();
        validate_report_golden("report-v2_5-execution.json", &good).unwrap();
        let cases = [
            (
                "/schema_version",
                json!("observed-crypto-v2.4"),
                "minor >= 5",
            ),
            (
                "/execution_attributions/0/selector",
                json!(1),
                "indexes no listed selector",
            ),
            (
                "/execution_attributions/0/offset",
                json!(9999),
                "no listed site",
            ),
            (
                "/execution_attributions/0/calls",
                json!(41),
                "site executed 40",
            ),
            (
                "/execution_attributions/0/end_ns",
                json!(91),
                "escape the site activity",
            ),
            (
                "/attribution_bounds/unresolved_calls",
                json!(51),
                "understates the 52-call",
            ),
        ];
        for (pointer, value, reason) in cases {
            let mut bad = good.clone();
            *bad.pointer_mut(pointer).unwrap() = value;
            // These shapes are legal JSON Schema; the cross-field checker must reject them.
            validate_v2(&bad).unwrap();
            let error = validate_report_golden("report-v2_5-execution.json", &bad).unwrap_err();
            assert!(error.contains(reason), "{pointer}: {error}");
        }
        let mut unknown = good;
        unknown["unexpected"] = json!(true);
        let error = validate_report_golden("report-v2_5-execution.json", &unknown).unwrap_err();
        assert!(
            error.contains("schema:") && error.contains("unexpected"),
            "{error}"
        );
    }

    #[test]
    fn no_v1_report_goldens_remain() {
        // Live producers are v2-only; historical v1 reader/auditor tests remain separate.
        for (name, doc) in report_goldens() {
            validate_report_golden(&name, &doc).unwrap_or_else(|e| panic!("{e}"));
        }
    }

    #[test]
    fn goldens_v2_conform_to_schema() {
        for (name, doc) in report_goldens() {
            validate_report_golden(&name, &doc).unwrap_or_else(|e| panic!("{e}"));
        }
        // The v2 auditor golden conforms too; the historical v1 auditor stays supported.
        let text = std::fs::read_to_string(format!(
            "{}/tests/auditor_golden_v2.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
        validate_report_golden("auditor_golden_v2.json", &doc).unwrap();
    }
}

#[cfg(test)]
mod g1_admission_reader_tests {
    use super::*;

    // Frozen pre-extension window schema; never derive it by deleting a field
    // from the current schema, which would hide compatibility regressions.
    const OLD_WINDOW_SCHEMA: &str = r#"{
        "type":"object","additionalProperties":false,
        "required":["requested_start_ns","requested_end_ns","effective_start_ns","effective_end_ns","signal_cut"],
        "properties":{
            "requested_start_ns":{"type":"integer","minimum":0,"maximum":18446744073709551615},
            "requested_end_ns":{"type":"integer","minimum":0,"maximum":18446744073709551615},
            "effective_start_ns":{"type":"integer","minimum":0,"maximum":18446744073709551615},
            "effective_end_ns":{"type":"integer","minimum":0,"maximum":18446744073709551615},
            "signal_cut":{"type":"boolean"}
        }
    }"#;

    #[test]
    fn g1_rendered_admission_rejected_by_frozen_pre_extension_validator() {
        let mut document = crate::capture::empty_document();
        document.window = crate::evidence::CaptureWindow {
            requested_start_ns: 1100,
            requested_end_ns: 2100,
            effective_start_ns: 1100,
            effective_end_ns: 1500,
            signal_cut: true,
            count_admission: Some(crate::evidence::CountAdmissionWindow {
                start_ns: 1000,
                deadline_ns: 2000,
            }),
        };
        document.status = crate::evidence::Completeness::Partial {
            reasons: vec![
                crate::evidence::GapReason::SignalCut,
                crate::evidence::GapReason::TailGap { missing_ns: 600 },
            ],
        };
        let bytes = crate::report::render_json(&document).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        validate_v2(&value).unwrap();
        check_v2_semantics(&value).unwrap();
        let old: serde_json::Value = serde_json::from_str(OLD_WINDOW_SCHEMA).unwrap();
        let error = validate_against(&old, &value["window"], &old, "$.window", 0).unwrap_err();
        assert!(error.path.contains("count_admission"));
        document.window.count_admission = None;
        let value: serde_json::Value =
            serde_json::from_slice(&crate::report::render_json(&document).unwrap()).unwrap();
        validate_v2(&value).unwrap();
        check_v2_semantics(&value).unwrap();
        validate_against(&old, &value["window"], &old, "$.window", 0).unwrap();
    }
}

// Optional observer metadata has the same closed shape even when the caller
// invokes semantics directly, without first invoking the schema validator.
fn check_preview_count_provenance(
    root: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), String> {
    let Some(value) = root.get("count_object") else {
        return Ok(());
    };
    let schema: serde_json::Value =
        serde_json::from_str(V2_SCHEMA_JSON).map_err(|e| e.to_string())?;
    validate_against(
        &schema["$defs"]["packageRoleProvenance"],
        value,
        &schema,
        "$.count_object",
        0,
    )
    .map_err(|e| e.to_string())?;
    let count: crate::package::commands::PackageRoleProvenance =
        serde_json::from_value(value.clone()).map_err(|e| format!("doc.count_object: {e}"))?;
    if count.build_input_id.is_some()
        || root.contains_key("package_build")
        || root.contains_key("selected_objects")
        || root.contains_key("traversal")
    {
        return Err("doc.count_object: count-only preview cannot claim a full bundle or authenticated build-input identity".into());
    }
    Ok(())
}

fn check_package_provenance(
    root: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), String> {
    use crate::package::commands::{
        PackageProvenance, PackageSelection, ROLE_BUFFER_LIMIT, RoleSelection,
    };
    let Some(value) = root.get("package_build") else {
        return Ok(());
    };
    let schema: serde_json::Value =
        serde_json::from_str(V2_SCHEMA_JSON).map_err(|e| e.to_string())?;
    validate_against(
        &schema["$defs"]["packageProvenance"],
        value,
        &schema,
        "$.package_build",
        0,
    )
    .map_err(|e| e.to_string())?;
    let p: PackageProvenance =
        serde_json::from_value(value.clone()).map_err(|e| format!("doc.package_build: {e}"))?;
    let fail = || "doc.package_build: inconsistent package/selected-object provenance".to_string();
    if let Some(base) = &p.installed_base {
        if base.source.revision.len() != 40
            || !base
                .source
                .revision
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || base.product_version.is_empty()
            || base.host_profile.abi_floor.is_empty()
            || base.tools.components_sha256.is_empty()
        {
            return Err(fail());
        }
        if !matches!(
            (
                base.host_profile.target.as_str(),
                base.host_profile.abi_profile.as_str()
            ),
            ("x86_64-unknown-linux-gnu", "linux-x86_64-gnu")
                | ("x86_64-unknown-linux-musl", "linux-x86_64-musl")
        ) {
            return Err(fail());
        }
    }
    let Some(count) = p.roles.count.as_ref() else {
        return Err(fail());
    };
    let selected = root
        .get("selected_objects")
        .and_then(|v| v.as_object())
        .ok_or_else(fail)?;
    if selected.get("members").is_some() != p.roles.members.is_some() {
        return Err(fail());
    }
    let mut total = 0u64;
    let mut explicit = 0;
    for (name, role) in [
        ("harvest", Some(&p.roles.harvest)),
        ("count", Some(count)),
        ("members", p.roles.members.as_ref()),
    ] {
        if let Some(role) = role {
            total = total.checked_add(role.bytes).ok_or_else(fail)?;
            if role.bytes == 0 || role.bytes > ROLE_BUFFER_LIMIT {
                return Err(fail());
            }
            match role.selection {
                RoleSelection::OperatorExplicit => {
                    explicit += 1;
                    if role.build_input_id.is_some() {
                        return Err(fail());
                    }
                }
                RoleSelection::InstalledMatched => {
                    if role.build_input_id.is_none()
                        || role.build_input_id != p.installed_base.as_ref().map(|b| b.input_id)
                    {
                        return Err(fail());
                    }
                }
            }
            let expected = role.sha256.to_string();
            if selected
                .get(name)
                .and_then(|r| r.get("sha256"))
                .and_then(|v| v.as_str())
                != Some(expected.as_str())
            {
                return Err(fail());
            }
            if let Some(traversal) = root.get("traversal") {
                if traversal
                    .get(name)
                    .and_then(|r| r.get("sha256"))
                    .and_then(|v| v.as_str())
                    != Some(expected.as_str())
                {
                    return Err(fail());
                }
            }
        }
    }
    if total > ROLE_BUFFER_LIMIT || (root.contains_key("traversal") && p.roles.members.is_none()) {
        return Err(fail());
    }
    match p.selection {
        PackageSelection::InstalledMatched
            if p.installed_base.is_none() || explicit != 0 || p.roles.members.is_none() =>
        {
            Err(fail())
        }
        PackageSelection::OperatorOverride if explicit == 0 => Err(fail()),
        _ => Ok(()),
    }
}

#[cfg(test)]
#[test]
fn package_frozen_v2_2_strict_reader_rejects_new_field() {
    // Exact public schema from 72f55991; SHA-256
    // a9a39ecf8ff99bcd85afdd998e392da1f73331ae9dcf75b5234894a93d9faefa.
    // This preimage was frozen before the package observer extension.
    #[path = "../tests/support/package_observer_fixtures.rs"]
    mod fixtures;
    let old: serde_json::Value = serde_json::from_str(include_str!(
        "../tests/support/observed_crypto_v2_2_schema.json"
    ))
    .unwrap();
    let mut v: serde_json::Value = serde_json::from_str(fixtures::HISTORICAL_V2_2).unwrap();
    validate_against(&old, &v, &old, "$", 0).unwrap();
    v["package_build"] = fixtures::package();
    v["selected_objects"] = fixtures::selection();
    let error = validate_against(&old, &v, &old, "$", 0).unwrap_err();
    assert_eq!(error.path, "$.package_build");
    assert!(error.message.contains("forbidden"));
    validate_v2(&v).unwrap();
    check_v2_semantics(&v).unwrap();
}

/// Optional v2.4 ledgers cannot create attribution or alter callback units.
fn check_dynamic_sections(root: &serde_json::Map<String, serde_json::Value>) -> Result<(), String> {
    use crate::evidence::{AlgorithmIdentity, SiteProvenance};
    use crate::provider_observation::MetadataOrigin;
    use std::collections::BTreeSet;
    fn section<T: serde::de::DeserializeOwned>(
        root: &serde_json::Map<String, serde_json::Value>,
        key: &str,
    ) -> Result<Vec<T>, String> {
        root.get(key)
            .map(|value| {
                serde_json::from_value(value.clone()).map_err(|_| format!("invalid {key}"))
            })
            .unwrap_or(Ok(Vec::new()))
    }
    let identities: Vec<AlgorithmIdentity> = section(root, "algorithm_identities")?;
    let provenance: Vec<SiteProvenance> = section(root, "site_provenance")?;
    let activity: Vec<crate::api_activity::ApiActivityRow> = section(root, "api_activity")?;
    let mut ids = BTreeSet::new();
    for identity in &identities {
        let valid = identity.id.strip_prefix("algorithm-").is_some_and(|hex| {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        });
        if !valid
            || !ids.insert(identity.id.as_str())
            || identity
                .known_algorithm
                .is_some_and(|id| id == u16::MAX || crate::kinds::alg_class_label(id).is_none())
        {
            return Err("invalid algorithm identity".into());
        }
    }
    let mut sites: Vec<&serde_json::Value> = root["sites"]
        .as_array()
        .ok_or("invalid sites")?
        .iter()
        .collect();
    for bucket in root["fenced"].as_array().ok_or("invalid fenced")? {
        sites.extend(bucket["sites"].as_array().ok_or("invalid fenced sites")?);
    }
    let mut seen = BTreeSet::new();
    for row in provenance {
        if !seen.insert((row.site.clone(), row.count_generation)) {
            return Err("duplicate provenance".into());
        }
        // Public physical rows flatten the backing identity (see site_json).
        let matched = sites.iter().find(|site| {
            site["object"].as_str() == Some(&row.site.object.0)
                && site["device"].as_u64() == Some(row.site.device)
                && site["inode"].as_u64() == Some(row.site.inode)
                && site["offset"].as_u64() == Some(row.site.offset)
                && site["generation"].as_u64() == Some(row.count_generation as u64)
        });
        if matched.is_none() {
            return Err("unresolved provenance site/generation".into());
        }
        if matched.is_some_and(|site| site["candidates_coverage"] != "unknown") {
            return Err("dynamic provenance cannot promote candidate coverage".into());
        }
        for a in row.associations {
            if a.algorithm_id
                .as_ref()
                .is_some_and(|id| !ids.contains(id.as_str()))
                || a.function_id == 0
                || a.function_id > i32::MAX as u32
                || a.operation
                    .is_some_and(|op| op == 0 || op > i32::MAX as u32)
                || a.observation_generation == 0
            {
                return Err("invalid candidate association".into());
            }
            match a.origin {
                MetadataOrigin::StaticPublicTableCandidate
                    if a.static_provenance.is_none()
                        || a.storage.is_none()
                        || !a.advertisers.is_empty() =>
                {
                    return Err("static shape cannot invent advertiser authority".into());
                }
                MetadataOrigin::ObservedPublicAbi
                    if a.static_provenance.is_some()
                        || a.storage.is_some()
                        || a.algorithm_id.is_none()
                        || a.operation.is_none() =>
                {
                    return Err("unsupported provenance promotion".into());
                }
                _ => {}
            }
        }
    }
    let mut apis = BTreeSet::new();
    for row in activity {
        let paired = row
            .observed_success
            .checked_add(row.observed_failure)
            .and_then(|v| v.checked_add(row.gaps.unsupported_return))
            .ok_or("API count overflow")?;
        let failure_subsets = row
            .verification_mismatch
            .checked_add(row.unsupported)
            .ok_or("API failure subset overflow")?;
        let api = u32::from(row.api);
        if !apis.insert(api)
            || row.gaps.not_attached && (row.entries != 0 || paired != 0)
            // PINS fix4: an unattached row can carry no read
            // receipt (nothing was admitted to read) — the
            // producer never emits this combination.
            || row.gaps.not_attached && row.gaps.read_receipt
            || paired > row.entries
            || row.gaps.tail != row.entries - paired
            || failure_subsets > row.observed_failure
            || row.verification_mismatch > 0 && !matches!(api, 40 | 45 | 47)
            || row.unsupported > 0 && !matches!(api, 39..=43 | 49..=58)
        {
            return Err("inconsistent API activity".into());
        }
    }
    Ok(())
}
