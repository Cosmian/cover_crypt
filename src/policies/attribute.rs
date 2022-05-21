#![allow(clippy::module_name_repetitions)]

use crate::error::Error;
use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt::Debug};

// An attribute in a policy group is characterized by the axis policy name
// and its unique name within the axis
#[derive(Hash, PartialEq, Eq, Clone, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "&str", into = "String")]
pub struct Attribute {
    axis: String,
    name: String,
}

impl Attribute {
    /// Create a Policy Attribute.
    pub fn new(axis: &str, name: &str) -> Self {
        Self {
            axis: axis.to_owned(),
            name: name.to_owned(),
        }
    }
    pub fn axis(&self) -> String {
        self.axis.to_owned()
    }

    pub fn name(&self) -> String {
        self.name.to_owned()
    }
}

impl Debug for Attribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}::{}", &self.axis, &self.name))
    }
}

impl From<(&str, &str)> for Attribute {
    fn from(input: (&str, &str)) -> Self {
        Attribute {
            axis: input.0.to_owned(),
            name: input.1.to_owned(),
        }
    }
}

impl From<(String, String)> for Attribute {
    fn from(input: (String, String)) -> Self {
        Attribute {
            axis: input.0,
            name: input.1,
        }
    }
}

impl TryFrom<&str> for Attribute {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let (axis, name) = s.trim().split_once("::").ok_or_else(|| {
            Error::InvalidAttribute(format!("at least one separator '::' expected in {s}"))
        })?;

        if name.contains("::") {
            return Err(Error::InvalidAttribute(format!(
                "separator '::' expected only once in {s}"
            )));
        }

        Ok(Self::new(axis, name))
    }
}

impl std::fmt::Display for Attribute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}::{}", self.axis, self.name)
    }
}

impl From<Attribute> for String {
    fn from(attr: Attribute) -> Self {
        attr.to_string()
    }
}
