// SPDX-License-Identifier: GPL-3.0-or-later
//! Strict private producer transport. Deliberately no Debug or serde for events.
use super::schema::*;
#[allow(dead_code)]
#[path = "../../crates/bpf-contract/src/provider_observation.rs"]
pub mod contract;
use contract as c;
pub struct ProviderEvent {
    pub(crate) record: c::Record,
    payload: ObservationPayload,
}
impl ProviderEvent {
    pub fn payload(&self) -> &ObservationPayload {
        &self.payload
    }
    pub(crate) fn into_payload(self) -> ObservationPayload {
        self.payload
    }
}
pub(crate) fn api(id: u32) -> Result<ObservationApi, ObservationGap> {
    use crate::inventory::Api::*;
    Ok(match id {
        1 => ObservationApi::Inventoried(OsslProviderLoad),
        2 => ObservationApi::Inventoried(OsslProviderTryLoad),
        3 => ObservationApi::Inventoried(OsslProviderLoadEx),
        4 => ObservationApi::Inventoried(OsslProviderTryLoadEx),
        5 => ObservationApi::Inventoried(OsslProviderUnload),
        6 => ObservationApi::Inventoried(OsslProviderAddBuiltin),
        7 => ObservationApi::Inventoried(OsslProviderInit),
        8 => ObservationApi::Inventoried(OsslProviderQueryOperation),
        9 => ObservationApi::OsslProviderUnqueryOperation,
        10 => ObservationApi::Inventoried(EvpMdFetch),
        11 => ObservationApi::Inventoried(EvpCipherFetch),
        12 => ObservationApi::Inventoried(EvpMacFetch),
        13 => ObservationApi::Inventoried(EvpKdfFetch),
        14 => ObservationApi::Inventoried(EvpSignatureFetch),
        15 => ObservationApi::Inventoried(EvpKemFetch),
        17 => ObservationApi::ProviderQueryCallback,
        18 => ObservationApi::ProviderTeardownCallback,
        19 => ObservationApi::ProviderUnqueryCallback,
        _ => return Err(ObservationGap::InvalidWire),
    })
}
fn outcome(v: u32) -> Result<ApiOutcome, ObservationGap> {
    Ok(match v {
        0 => ApiOutcome::Unknown,
        1 => ApiOutcome::Success,
        2 => ApiOutcome::Failure,
        _ => return Err(ObservationGap::InvalidWire),
    })
}
fn cache(v: u32) -> Result<Cacheability, ObservationGap> {
    Ok(match v {
        0 => Cacheability::Unknown,
        1 => Cacheability::Cacheable,
        2 => Cacheability::Volatile,
        _ => return Err(ObservationGap::InvalidWire),
    })
}
fn name(v: u32) -> Result<ProviderNameClass, ObservationGap> {
    Ok(match v {
        0 => ProviderNameClass::Other,
        1 => ProviderNameClass::Legacy,
        2 => ProviderNameClass::Default,
        3 => ProviderNameClass::Fips,
        4 => ProviderNameClass::Unreadable,
        5 => ProviderNameClass::Overlong,
        _ => return Err(ObservationGap::InvalidWire),
    })
}
fn read_record(bytes: &[u8]) -> Result<c::Record, ObservationGap> {
    if bytes.len() != c::EVENT_SIZE {
        return Err(ObservationGap::InvalidWire);
    }
    // All fields are plain integers; exact-size checked, no enum/padding dereference.
    let r = unsafe { bytes.as_ptr().cast::<c::Record>().read_unaligned() };
    Ok(r)
}
pub fn decode(bytes: &[u8]) -> Result<ProviderEvent, ObservationGap> {
    decode_record(read_record(bytes)?)
}
fn decode_record(r: c::Record) -> Result<ProviderEvent, ObservationGap> {
    let bad = ObservationGap::InvalidWire;
    if r.version != c::VERSION
        || r.size != c::EVENT_SIZE as u32
        || r.reserved != [0; 2]
        || r.cookie == 0
        || r.generation == 0
        || r.pid == 0
        || r.tid == 0
        || r.invocation == 0
    {
        return Err(bad);
    }
    api(r.api)?;
    let op = Operation::from_id(r.operation).ok_or(bad)?;
    outcome(r.outcome)?;
    cache(r.cacheability)?;
    if r.code != 0
        && !(r.kind == c::INIT
            || r.kind == c::IMPLEMENTATION && r.cacheability == 1 && r.function != 0)
    {
        return Err(bad);
    }
    if r.code != 0 && !(4096..=0x0000_ffff_ffff_ffff).contains(&r.code) {
        return Err(bad);
    }
    let compatible = match r.kind {
        c::ATTEMPT | c::RESULT => matches!(r.api,1..=6|10..=15),
        c::INIT => {
            r.api == c::PROVIDER_INIT && r.function != 1
                || r.api == c::ADD_BUILTIN && r.function == 1
        }
        c::QUERY | c::IMPLEMENTATION => c::query_api(r.api),
        c::INVALIDATION => matches!(
            r.api,
            c::UNLOAD | c::PUBLIC_UNQUERY | c::TEARDOWN | c::UNQUERY_CALLBACK
        ),
        _ => false,
    };
    if !compatible {
        return Err(bad);
    }
    let payload = match r.kind {
        c::ATTEMPT | c::RESULT => {
            if r.operation != 0
                || r.algorithm != 0
                || r.function != 0
                || r.cacheability != 0
                || (r.kind == c::ATTEMPT && r.outcome != 0)
            {
                return Err(bad);
            }
            if r.kind == c::ATTEMPT {
                ObservationPayload::ApiAttempt {
                    name: name(r.status)?,
                }
            } else {
                ObservationPayload::ApiResult {
                    name: name(r.status)?,
                    outcome: outcome(r.outcome)?,
                }
            }
        }
        c::INIT => {
            if r.operation != 0
                || r.algorithm != 0
                || r.status != 0
                || r.cacheability != 0
                || !matches!(r.function, 0 | 1024 | 1027 | 1028 | 1)
                || r.code != 0 && r.outcome != 1
                || r.code == 0 && r.function != 0
            {
                return Err(bad);
            }
            ObservationPayload::InitResult {
                outcome: outcome(r.outcome)?,
            }
        }
        c::QUERY => {
            if r.algorithm != 0 || r.function != 0 || r.status != 0 {
                return Err(bad);
            }
            ObservationPayload::QueryResult {
                outcome: outcome(r.outcome)?,
                cacheability: cache(r.cacheability)?,
            }
        }
        c::IMPLEMENTATION => {
            if r.outcome != 0 || r.status != 0 || r.algorithm != c::OTHER {
                return Err(bad);
            }
            let function = FunctionIdentity::new(op, r.function).map_err(|_| bad)?;
            ObservationPayload::Implementation {
                algorithm: AlgorithmId::try_from(u16::MAX).unwrap(),
                function,
                cacheability: cache(r.cacheability)?,
                advertiser_candidates: Vec::new(),
                backing_sha256: None,
            }
        }
        c::INVALIDATION => {
            if r.outcome != 0
                || r.operation != 0
                || r.algorithm != 0
                || r.function != 0
                || r.cacheability != 0
            {
                return Err(bad);
            }
            let cause = match r.status {
                1 => InvalidationCause::Unload,
                2 => InvalidationCause::Unquery,
                3 => InvalidationCause::Teardown,
                4 => InvalidationCause::IdentityChanged,
                _ => return Err(bad),
            };
            ObservationPayload::Invalidation { cause }
        }
        _ => return Err(bad),
    };
    Ok(ProviderEvent { record: r, payload })
}

pub(crate) enum Transport {
    Event(ProviderEvent),
    Alias(c::Record),
    End(c::Record),
}
impl Transport {
    pub(crate) fn record(&self) -> c::Record {
        match self {
            Self::Event(e) => e.record,
            Self::Alias(r) | Self::End(r) => *r,
        }
    }
}
pub(crate) fn decode_transport(bytes: &[u8]) -> Result<Transport, ObservationGap> {
    let r = read_record(bytes)?;
    if !matches!(r.kind, c::ALIAS | c::ALIAS_END) {
        return decode_record(r).map(Transport::Event);
    }
    // Reuse the complete envelope/query validation, retaining code and reserved
    // slots so internal records cannot smuggle relocation operands or extensions.
    let mut envelope = r;
    envelope.kind = c::QUERY;
    envelope.algorithm = 0;
    envelope.function = 0;
    envelope.outcome = 0;
    envelope.status = 0;
    decode_record(envelope)?;
    let bad = ObservationGap::InvalidWire;
    if r.kind == c::ALIAS {
        if r.status >= 8 || r.outcome > 1 || r.algorithm > c::OTHER || r.function > c::OTHER {
            return Err(bad);
        }
        if r.algorithm == c::OTHER {
            if r.function != c::OTHER {
                return Err(bad);
            }
        } else {
            let label = crate::kinds::alg_class_label(r.algorithm as u16).ok_or(bad)?;
            if crate::kinds::algorithm_semantic_id(label) != Some(r.function as u16)
                || u32::from(crate::kinds::is_weak_alg(label)) != r.outcome
            {
                return Err(bad);
            }
        }
        Ok(Transport::Alias(r))
    } else {
        if r.algorithm != c::OTHER
            || r.outcome != 0
            || !matches!((r.status, r.function), (0, 1..=8) | (3, 8) | (2 | 4, 0))
        {
            return Err(bad);
        }
        Ok(Transport::End(r))
    }
}
pub(crate) fn algorithm_event(mut record: c::Record, algorithm: AlgorithmId) -> ProviderEvent {
    record.kind = c::ALGORITHM;
    ProviderEvent {
        record,
        payload: ObservationPayload::Algorithm {
            algorithm,
            cacheability: cache(record.cacheability).unwrap_or(Cacheability::Unknown),
        },
    }
}
