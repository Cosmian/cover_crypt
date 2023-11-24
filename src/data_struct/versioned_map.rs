use std::{
    collections::{hash_map::Entry, HashMap, LinkedList},
    fmt::Debug,
    hash::Hash,
    iter,
};

type Version = u32;
/// a `VersionedMap` stores linked lists.
#[derive(Default, Debug, PartialEq, Eq)]
pub struct VersionedMap<K, V>
where
    K: Debug + PartialEq + Eq + Hash,
    V: Debug,
{
    pub(crate) map: HashMap<K, LinkedList<(Version, V)>>,
    len: usize,
}

impl<K, V> VersionedMap<K, V>
where
    K: Hash + PartialEq + Eq + Clone + Debug,
    V: Clone + Debug,
{
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            len: 0,
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            map: HashMap::with_capacity(capacity),
            len: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Inserts value at key and return the current version for this key.
    pub fn insert(&mut self, key: K, value: V) -> usize {
        match self.map.entry(key) {
            Entry::Occupied(mut entry) => {
                // TODO: fix
                entry.get_mut().push_front((2, value));
                2
            }
            Entry::Vacant(entry) => {
                let mut list = LinkedList::new();
                list.push_front((1, value));
                entry.insert(list);
                1
            }
        }
    }

    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.map.keys()
    }

    /// Iterates through all values in depth first.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.map
            .iter()
            .flat_map(|(k, chain)| chain.iter().map(move |(_, v)| (k, v)))
    }

    /// Iterates through all values from a link chain.
    pub fn iter_chain<'a>(&'a self, key: &K) -> Box<dyn 'a + Iterator<Item = &V>> {
        match self.map.get(key) {
            Some(chain) => Box::new(chain.iter().map(|(_, v)| v)),
            None => Box::new(iter::empty()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_versioned_hashmap() -> Result<(), Error> {
        Ok(())
    }
}
