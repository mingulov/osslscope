// SPDX-License-Identifier: GPL-3.0-or-later
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageError {
    Unavailable { context: String },
    Invalid { context: String },
    Untrusted { context: String },
    Unreadable { context: String },
    Mutated { context: String },
}

impl PackageError {
    pub fn invalid(context: impl AsRef<str>) -> Self {
        Self::Invalid {
            context: bounded(context.as_ref()),
        }
    }
    pub fn unavailable(context: impl AsRef<str>) -> Self {
        Self::Unavailable {
            context: bounded(context.as_ref()),
        }
    }
    pub fn unreadable(context: impl AsRef<str>) -> Self {
        Self::Unreadable {
            context: bounded(context.as_ref()),
        }
    }
}

fn bounded(value: &str) -> String {
    value.chars().take(160).collect()
}

impl fmt::Display for PackageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable { context } => write!(f, "unavailable package metadata: {context}"),
            Self::Invalid { context } => write!(f, "invalid package metadata: {context}"),
            Self::Untrusted { context } => write!(f, "untrusted package metadata: {context}"),
            Self::Unreadable { context } => write!(f, "unreadable package metadata: {context}"),
            Self::Mutated { context } => write!(f, "mutated package metadata: {context}"),
        }
    }
}

impl std::error::Error for PackageError {}
