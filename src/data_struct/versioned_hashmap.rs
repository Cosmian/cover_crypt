use std::{
    collections::{
        hash_map::{Entry, OccupiedEntry},
        HashMap,
    },
    fmt::Debug,
    hash::Hash,
};

use super::error::Error;

/// a `VersionedHashMap` stores flat linked lists where each element can be
/// accessed in constant time. Each map entry contains the element value as well
/// as optional keys of the next and prev element version in the hash map.
///
/// Map {       value       prev    next
///     k1  : { data v1,  None,   k1'  }
///     k2  : {     ...,  None,   None }
///     k1' : { data v2,  k1,     k1"  }
///     k3  : { value 1,  None,   k3'  }
///     k3' : { value 2,  k3,     None }
///     k1'': { data v3,  k1',    None }
/// }
///
/// The element versions are stored in chronological order.
/// New element versions can only be added at the back of the chain and removing
/// one element of a linked list will remove all previous versions as well.
#[derive(Default, Debug, PartialEq, Eq)]
pub struct VersionedHashMap<K, V>
where
    K: Debug + PartialEq + Eq + Hash,
    V: Debug + PartialEq + Eq,
{
    map: HashMap<K, VersionedEntry<K, V>>,
}

/// a `VersionedEntry` stores a value and an optional key of the next entry
/// version in the hash map.
#[derive(Debug, PartialEq, Eq, Clone)]
struct VersionedEntry<K, V> {
    value: V,
    prev_key: Option<K>,
    next_key: Option<K>,
}

impl<K, V> VersionedEntry<K, V>
where
    V: Clone,
{
    pub fn new(value: V, prev_key: Option<K>) -> Self {
        Self {
            value,
            prev_key,
            next_key: None,
        }
    }

    pub fn get_value(&self) -> &V {
        &self.value
    }
}

struct VersionedHashMapIterator<'a, K, V>
where
    K: Debug + PartialEq + Eq + Hash,
    V: Debug + PartialEq + Eq,
{
    lhm: &'a VersionedHashMap<K, V>,
    current_key: Option<&'a K>,
}

impl<'a, K, V> Iterator for VersionedHashMapIterator<'a, K, V>
where
    V: Clone + Debug + Eq + PartialEq,
    K: Hash + Eq + PartialEq + Clone + PartialOrd + Ord + Debug,
{
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        self.current_key.and_then(|key| {
            self.lhm.get_versioned_entry(key).map(|entry| {
                self.current_key = entry.next_key.as_ref();
                (key, entry.get_value())
            })
        })
    }
}

impl<K, V> VersionedHashMap<K, V>
where
    K: Hash + PartialEq + Eq + Clone + PartialOrd + Ord + Debug,
    V: Clone + Debug + PartialEq + Eq,
{
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            map: HashMap::with_capacity(capacity),
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Internal pattern matching
    fn expected_entry(&mut self, key: K) -> Result<OccupiedEntry<K, VersionedEntry<K, V>>, Error> {
        match self.map.entry(key) {
            Entry::Occupied(e) => Ok(e),
            Entry::Vacant(e) => Err(Error::missing_entry(e.key())),
        }
    }

    /// Get internal entry
    fn get_versioned_entry(&self, key: &K) -> Option<&VersionedEntry<K, V>> {
        self.map.get(key)
    }

    pub fn insert_root(&mut self, key: K, value: V) -> Result<(), Error> {
        match self.map.entry(key.clone()) {
            Entry::Occupied(_) => Err(Error::existing_entry(&key)),
            Entry::Vacant(entry) => {
                entry.insert(VersionedEntry::new(value, None));
                //self.roots.push(key);
                //self.roots.sort(); // allow binary search when removing root
                Ok(())
            }
        }
    }

    pub fn insert(&mut self, parent_key: &K, key: K, value: V) -> Result<(), Error> {
        // Get parent from hashmap and check that it does not already have a child
        let parent_entry = match self.map.get(parent_key) {
            Some(linked_entry) => Ok(linked_entry),
            None => Err(Error::missing_entry(parent_key)),
        }?;
        if parent_entry.next_key.is_some() {
            return Err(Error::already_has_child(parent_key));
        }

        // Insert new key-value pair in hashmap and set parent child
        match self.map.entry(key.clone()) {
            Entry::Occupied(_) => Err(Error::existing_entry(&key)),
            Entry::Vacant(entry) => {
                entry.insert(VersionedEntry::new(value, Some(parent_key.clone())));
                // cannot hold mutable reference from parent_entry
                self.map
                    .get_mut(parent_key)
                    .expect("checked above")
                    .next_key = Some(key);
                Ok(())
            }
        }
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key).map(VersionedEntry::get_value)
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }

    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.map.keys()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.map.iter().map(|(k, entry)| (k, &entry.value))
    }

    /// Iterates through all values from a link chain.
    pub fn iter_chain<'a>(&'a self, key: &'a K) -> impl Iterator<Item = (&K, &V)> + 'a {
        VersionedHashMapIterator::<'a, K, V> {
            lhm: self,
            current_key: Some(key),
        }
    }

    /// Removes all parents of the given entry version, making it the oldest
    /// stored version.
    pub fn set_chain_parent(&mut self, key: K) -> Result<(), Error> {
        // Get and remove prev_key from the given entry
        let mut prev_key = self.expected_entry(key)?.get_mut().prev_key.take();

        // Go through all previous entries and remove them
        while let Some(key) = prev_key.take() {
            let mut curr_entry = self.expected_entry(key)?;
            prev_key = curr_entry.get_mut().prev_key.take();
            curr_entry.remove_entry();
        }

        Ok(())
    }

    // Removes all but the last (key, value) pair from a link chain.
    // pub fn pop_chain(&mut self, root_key: K) -> Result<(), Error> {
    //      let mut curr_entry = self.expected_entry(root_key)?;
    //
    //      while our current entry has a next key, we remove it from the hashmap
    //      while let Some(next_key) = curr_entry.get_mut().next_key.take() {
    //          curr_entry.remove_entry();
    //          curr_entry = self.expected_entry(next_key)?;
    //      }
    //
    //      Ok(())
    //  }
}

#[test]
fn test_versioned_hashmap() -> Result<(), Error> {
    let mut lhm = VersionedHashMap::new();

    lhm.insert_root(1, "key1".to_string())?;
    lhm.insert_root(2, "key2".to_string())?;
    lhm.insert_root(3, "key3".to_string())?;

    lhm.insert(&1, 11, "key11".to_string())?;
    assert!(lhm.insert(&1, 12, "key12".to_string()).is_err());
    lhm.insert(&11, 111, "key111".to_string())?;

    assert_eq!(lhm.get(&1), Some(&"key1".to_string()));
    assert_eq!(lhm.get(&11), Some(&"key11".to_string()));

    let res: Vec<_> = lhm.iter().collect();
    assert_eq!(res.len(), 5);

    let res: Vec<_> = lhm.iter_chain(&1).collect();
    assert_eq!(
        res,
        vec![
            (&1, &"key1".to_string()),
            (&11, &"key11".to_string()),
            (&111, &"key111".to_string())
        ]
    );

    lhm.set_chain_parent(111)?;
    assert_eq!(lhm.len(), 3);

    Ok(())
}
