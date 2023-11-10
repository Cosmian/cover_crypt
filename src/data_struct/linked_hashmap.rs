use std::{
    collections::{
        hash_map::{Entry, OccupiedEntry},
        HashMap,
    },
    hash::Hash,
};

use crate::Error;

struct LinkedEntry<K, V>
where
    V: Clone,
{
    value: V,
    next_key: Option<K>,
}

impl<K, V> LinkedEntry<K, V>
where
    V: Clone,
{
    pub fn new(value: V) -> Self {
        LinkedEntry {
            value,
            next_key: None,
        }
    }

    pub fn get_value(&self) -> &V {
        &self.value
    }
}

struct LinkedHashMapIterator<'a, K, V>
where
    V: Clone,
    K: Hash + Eq + PartialEq + Clone + PartialOrd + Ord,
{
    lhm: &'a LinkedHashMap<K, V>,
    current_key: Option<&'a K>,
}

impl<'a, K, V> Iterator for LinkedHashMapIterator<'a, K, V>
where
    V: Clone,
    K: Hash + Eq + PartialEq + Clone + PartialOrd + Ord,
{
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        self.current_key.and_then(|key| {
            self.lhm.get_link_entry(key).map(|entry| {
                self.current_key = entry.next_key.as_ref();
                (key, entry.get_value())
            })
        })
    }
}

#[derive(Default)]
pub struct LinkedHashMap<K, V>
where
    K: Hash + PartialEq + Eq + Clone + PartialOrd + Ord,
    V: Clone,
{
    map: HashMap<K, LinkedEntry<K, V>>,
    //roots: Vec<K>,
}

impl<K, V> LinkedHashMap<K, V>
where
    K: Hash + PartialEq + Eq + Clone + PartialOrd + Ord,
    V: Clone,
{
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            //roots: Vec::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            map: HashMap::with_capacity(capacity),
            //roots: Vec::with_capacity(capacity),
        }
    }

    /// Internal pattern matching
    fn expected_entry(&mut self, key: K) -> Result<OccupiedEntry<K, LinkedEntry<K, V>>, Error> {
        match self.map.entry(key) {
            Entry::Occupied(e) => Ok(e),
            Entry::Vacant(_) => Err(Error::KeyError("Key not found".to_string())),
        }
    }

    /// Get internal type
    fn get_link_entry(&self, key: &K) -> Option<&LinkedEntry<K, V>> {
        self.map.get(key)
    }

    pub fn insert_root(&mut self, key: K, value: V) -> Result<(), Error> {
        match self.map.entry(key.clone()) {
            Entry::Occupied(_) => Err(Error::KeyError("Key is already used".to_string())),
            Entry::Vacant(entry) => {
                entry.insert(LinkedEntry::new(value));
                //self.roots.push(key);
                //self.roots.sort(); // allow binary search when removing root
                Ok(())
            }
        }
    }

    pub fn insert(&mut self, parent_key: &K, key: K, value: V) -> Result<(), Error> {
        let parent_entry = match self.map.get(parent_key) {
            Some(linked_entry) => Ok(linked_entry),
            None => Err(Error::KeyError("Parent key not found".to_string())),
        }?;

        if parent_entry.next_key.is_some() {
            return Err(Error::KeyError(
                "Parent already contains a next key".to_string(),
            ));
        }

        match self.map.entry(key.clone()) {
            Entry::Occupied(_) => Err(Error::KeyError("Key is already used".to_string())),
            Entry::Vacant(entry) => {
                entry.insert(LinkedEntry::new(value));
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
        self.map.get(key).map(LinkedEntry::get_value)
    }

    pub fn iter_link<'a>(&'a self, key: &'a K) -> impl Iterator<Item = (&K, &V)> + 'a {
        LinkedHashMapIterator::<'a, K, V> {
            lhm: self,
            current_key: Some(key),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.map.iter().map(|(k, entry)| (k, &entry.value))
    }

    /// Remove all but the last (key, value) pair from a link
    pub fn pop_chain(&mut self, root_key: K) -> Result<(), Error> {
        let mut curr_entry = self.expected_entry(root_key)?;

        // while our current entry has a next key, we remove it from the hashmap
        while let Some(next_key) = curr_entry.get_mut().next_key.take() {
            curr_entry.remove_entry();
            curr_entry = self.expected_entry(next_key)?;
        }

        Ok(())
    }
}

#[test]
fn test_linked_hashmap() -> Result<(), Error> {
    let mut lhm = LinkedHashMap::new();

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

    let res: Vec<_> = lhm.iter_link(&1).collect();
    assert_eq!(
        res,
        vec![
            (&1, &"key1".to_string()),
            (&11, &"key11".to_string()),
            (&111, &"key111".to_string())
        ]
    );

    lhm.pop_chain(1)?;
    let res: Vec<_> = lhm.iter().collect();
    assert_eq!(res.len(), 3);

    Ok(())
}
