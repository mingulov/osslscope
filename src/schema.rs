//! SPDX-License-Identifier: GPL-3.0-or-later
//! `observed-crypto-v1` reader contract (P3 exit-3).
//!
//! The schema file lives at `schemas/observed-crypto-v1.json`.
//! Readers accept v1.x documents and reject other majors or
//! garbage (`check_version`); producers emit `observed-crypto-v1.0`
//! today. Minor versions add OPTIONAL keys only — readers must
//! ignore unknown keys.

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

/// Assert a document carries every `required` key in the schema
/// (recursive over properties/items; nulls and absent optionals
/// skipped). Structural pin for goldens — external consumers use
/// real JSON-Schema validators against the schema file.
#[cfg(test)]
pub(crate) fn assert_required_keys(schema: &serde_json::Value, doc: &serde_json::Value) {
    fn walk(schema: &serde_json::Value, doc: &serde_json::Value, path: &str) {
        if let Some(req) = schema.get("required").and_then(|v| v.as_array()) {
            let obj = doc
                .as_object()
                .unwrap_or_else(|| panic!("{path}: not an object"));
            for k in req {
                let k = k.as_str().unwrap();
                assert!(obj.contains_key(k), "{path}: missing required key '{k}'");
            }
        }
        if let Some(props) = schema.get("properties").and_then(|v| v.as_object()) {
            for (k, sub) in props {
                if let Some(d) = doc.get(k) {
                    if d.is_null() {
                        continue;
                    }
                    walk(sub, d, &format!("{path}.{k}"));
                }
            }
        }
        if let Some(items) = schema.get("items") {
            if let Some(arr) = doc.as_array() {
                for (i, d) in arr.iter().enumerate() {
                    walk(items, d, &format!("{path}[{i}]"));
                }
            }
        }
    }
    walk(schema, doc, "$");
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
/// OPTIONAL keys only — readers must ignore unknown keys.
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
        Some(m) => !m.is_empty() && m.bytes().all(|b| b.is_ascii_digit()),
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
    let schema: serde_json::Value =
        serde_json::from_str(V2_SCHEMA_JSON).map_err(|e| SchemaError {
            path: "$".to_string(),
            message: format!("v2 schema file is not valid JSON: {e}"),
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
/// timestamp order and key uniqueness, status/reasons agreement,
/// policy verdict combination with definite-within-possible bounds
/// and per-site evidence totals, and fenced-bucket generation
/// agreement. Fails closed on malformed shape (this runs after
/// [`validate_v2`] in the normal pipeline, but never assumes it
/// did).
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
    check_window(root)?;
    check_object_refs(root)?;
    check_records(root)?;
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

fn check_window(root: &serde_json::Map<String, serde_json::Value>) -> Result<(), String> {
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
    Ok(())
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

fn check_object_refs(root: &serde_json::Map<String, serde_json::Value>) -> Result<(), String> {
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
        }
    }
    Ok(())
}

fn check_records(root: &serde_json::Map<String, serde_json::Value>) -> Result<(), String> {
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
                "environment" => {
                    if !detail {
                        return Err(
                            "doc.completeness.fatal_kind: environment needs detail".to_string()
                        );
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
    // Site timestamps order (first touch precedes last touch).
    let check_times = |site: &serde_json::Value, ctx: &str| -> Result<(), String> {
        let record = site
            .as_object()
            .ok_or_else(|| format!("{ctx}: expected object"))?;
        let first = get_u64(record, "first_ns", ctx)?;
        let last = get_u64(record, "last_ns", ctx)?;
        if first > last {
            return Err(format!("{ctx}: first_ns {first} is past last_ns {last}"));
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
    // Policy verdict is the AND of its rules: any violation rules
    // the verdict a violation, else any inconclusive rules it
    // inconclusive, else pass. `no-verdict` rides FATAL documents
    // only (and FATAL documents with policy carry exactly that).
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
        if status == "FATAL" {
            if verdict != "no-verdict" {
                return Err("doc.policy: FATAL documents carry no-verdict".to_string());
            }
        } else if verdict == "no-verdict" {
            return Err("doc.policy: no-verdict on a non-fatal document".to_string());
        } else if verdict != combined {
            return Err(format!(
                "doc.policy: verdict {verdict:?} contradicts rule results {results:?}"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn compat_matrix_v2() {
        assert!(check_version_v2("observed-crypto-v2.0"));
        assert!(check_version_v2("observed-crypto-v2.9"));
        assert!(check_version_v2("observed-crypto-v2"));
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
    fn goldens_conform_to_schema() {
        let dir = format!("{}/tests/goldens", env!("CARGO_MANIFEST_DIR"));
        let schema: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(format!(
                "{}/schemas/observed-crypto-v1.json",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap(),
        )
        .unwrap();
        let mut n = 0;
        let mut entries: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_str().unwrap().to_string())
            // v1 files only (`report-v2-*` conform to the v2 schema
            // under `goldens_v2_conform_to_schema` below).
            .filter(|f| {
                f.starts_with("report-") && !f.starts_with("report-v2-") && f.ends_with(".json")
            })
            .collect();
        entries.sort();
        for f in entries {
            let doc: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(format!("{dir}/{f}")).unwrap())
                    .unwrap();
            let v = doc["schema_version"].as_str().unwrap();
            assert!(check_version(v), "{f}: reader rejects {v}");
            assert!(!check_version_v2(v), "{f}: v1 file accepted by v2 reader");
            assert_required_keys(&schema, &doc);
            n += 1;
        }
        assert!(n >= 8, "expected report goldens, found {n}");
    }

    #[test]
    fn goldens_v2_conform_to_schema() {
        // Every checked-in v2 artifact validates (schema +
        // semantics) on every run: goldens cannot rot into
        // non-conforming bytes unnoticed.
        let dir = format!("{}/tests/goldens", env!("CARGO_MANIFEST_DIR"));
        let mut entries: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_str().unwrap().to_string())
            .filter(|f| f.starts_with("report-v2-") && f.ends_with(".json"))
            .collect();
        entries.sort();
        for f in &entries {
            let doc: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(format!("{dir}/{f}")).unwrap())
                    .unwrap();
            let v = doc["schema_version"].as_str().unwrap();
            assert!(check_version_v2(v), "{f}: v2 reader rejects {v}");
            assert!(!check_version(v), "{f}: v2 file accepted by v1 reader");
            validate_v2(&doc).unwrap_or_else(|e| panic!("{f}: schema: {e}"));
            check_v2_semantics(&doc).unwrap_or_else(|e| panic!("{f}: semantics: {e}"));
        }
        assert!(
            entries.len() >= 5,
            "expected v2 report goldens, found {}",
            entries.len()
        );
        // The v2 auditor golden conforms too (same checker the
        // auditor suite uses).
        let text = std::fs::read_to_string(format!(
            "{}/tests/auditor_golden_v2.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let doc: serde_json::Value = serde_json::from_str(&text).unwrap();
        validate_v2(&doc).expect("auditor golden v2: schema");
        check_v2_semantics(&doc).expect("auditor golden v2: semantics");
    }
}
