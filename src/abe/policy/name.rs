use crate::{
    Error,
    abe::policy::access_policy::{AccessPolicyParser, Rule},
};
use cosmian_crypto_core::bytes_ser_de::{
    Deserializer, Serializable, Serializer,
};
use pest::Parser;
use serde::{Deserialize, Serialize};
use std::{borrow::Borrow, ops::Deref};

pub const BROADCAST: &str = "*";

fn validate_name(name: &str) -> Result<(), Error> {
    if name == BROADCAST {
        return Err(Error::InvalidName(
            "broadcast '*' is not a valid name".to_owned(),
        ));
    }

    let ident = AccessPolicyParser::parse(Rule::ident, name)
        .map_err(|_| Error::InvalidAccessPolicy(name.to_owned()))?
        .next()
        .ok_or_else(|| Error::InvalidAccessPolicy(name.to_owned()))?;

    if name != ident.as_span().as_str() {
        return Err(Error::InvalidName(format!(
            "failed to match a valid token in '{}' after '{}'",
            name.to_owned(),
            ident.as_span().as_str()
        )));
    }
    Ok(())
}

#[derive(Clone, Debug, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub struct NameRef<'a>(&'a str);

impl<'a> Deref for NameRef<'a> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl<'a> TryFrom<&'a str> for NameRef<'a> {
    type Error = Error;

    fn try_from(name: &'a str) -> Result<Self, Self::Error> {
        validate_name(name).map(|_| Self(name))
    }
}

#[derive(
    Clone, Debug, Hash, Ord, PartialOrd, Eq, PartialEq, Serialize, Deserialize,
)]
#[serde(try_from = "String", into = "String")]
pub struct Name(String);

impl Deref for Name {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Borrow<str> for Name {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl From<Name> for String {
    fn from(name: Name) -> Self {
        name.0
    }
}

impl TryFrom<String> for Name {
    type Error = Error;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        validate_name(&name).map(|_| Self(name))
    }
}

impl<'a> From<&'a Name> for NameRef<'a> {
    fn from(name: &'a Name) -> Self {
        NameRef(&name.0)
    }
}

impl<'a> From<NameRef<'a>> for Name {
    fn from(value: NameRef<'a>) -> Self {
        Self(value.to_string())
    }
}

impl Serializable for Name {
    type Error = Error;

    fn length(&self) -> usize {
        self.0.length()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        ser.write(&self.0).map_err(Error::from)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        de.read().map(Self).map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use crate::abe::policy::name::validate_name;

    #[test]
    fn test_names() {
        assert!(validate_name("A-1").is_ok());
        assert!(validate_name("AB-1b-1-1-1").is_ok());
        assert!(validate_name("A----1").is_err());
        assert!(validate_name("1-A").is_err());
        assert!(validate_name("*").is_err());
    }
}
