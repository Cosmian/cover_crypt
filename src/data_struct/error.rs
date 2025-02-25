use std::fmt::{Debug, Display};

type Key = String;

#[derive(Debug)]
pub enum Error {
    EntryNotFound(Key),
    ExistingEntry(Key),
    AlreadyHasChild(Key),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            Self::EntryNotFound(key) => write!(f, "Entry not found with key: {key}."),
            Self::ExistingEntry(key) => write!(f, "Already existing entry with key: {key}."),
            Self::AlreadyHasChild(key) => {
                write!(f, "Entry with key {key} already has a child.")
            }
        }
    }
}

impl Error {
    pub fn missing_entry<T>(key: &T) -> Self
    where
        T: Debug,
    {
        Self::EntryNotFound(format!("{key:?}"))
    }

    pub fn existing_entry<T>(key: &T) -> Self
    where
        T: Debug,
    {
        Self::ExistingEntry(format!("{key:?}"))
    }

    pub fn already_has_child<T>(key: &T) -> Self
    where
        T: Debug,
    {
        Self::AlreadyHasChild(format!("{key:?}"))
    }
}
