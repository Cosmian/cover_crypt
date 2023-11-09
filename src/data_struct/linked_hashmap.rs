use std::{
    collections::{hash_map::Entry, HashMap},
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
    type Item = &'a V;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(key) = self.current_key {
            match self.lhm.get_link_entry(key) {
                Some(entry) => {
                    self.current_key = entry.next_key.as_ref();
                    Some(entry.get_value())
                }
                None => None,
            }
        } else {
            None
        }
    }
}

#[derive(Default)]
pub struct LinkedHashMap<K, V>
where
    K: Hash + PartialEq + Eq + Clone + PartialOrd + Ord,
    V: Clone,
{
    map: HashMap<K, LinkedEntry<K, V>>,
    roots: Vec<K>,
}

impl<K, V> LinkedHashMap<K, V>
where
    K: Hash + PartialEq + Eq + Clone + PartialOrd + Ord,
    V: Clone,
{
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            roots: Vec::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            map: HashMap::with_capacity(capacity),
            roots: Vec::with_capacity(capacity),
        }
    }

    pub fn insert_root(&mut self, key: K, value: V) -> Result<(), Error> {
        match self.map.entry(key.clone()) {
            Entry::Occupied(_) => Err(Error::KeyError("Key is already used".to_string())),
            Entry::Vacant(entry) => {
                entry.insert(LinkedEntry::new(value));
                self.roots.push(key);
                self.roots.sort(); // allow binary search when removing root
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

    fn get_link_entry(&self, key: &K) -> Option<&LinkedEntry<K, V>> {
        self.map.get(key)
    }

    pub fn iter_link<'a>(&'a self, key: &'a K) -> impl Iterator<Item = &V> + 'a {
        LinkedHashMapIterator::<'a, K, V> {
            lhm: self,
            current_key: Some(key),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.map.iter().map(|(k, entry)| (k, &entry.value))
    }

    /// Remove all but the last (key, value) pair from a link
    pub fn pop_link(&mut self, root_key: K) -> Result<(), Error> {
        let root_index = self
            .roots
            .binary_search(&root_key)
            .map_err(|_| Error::KeyError("Root key not found".to_string()))?;

        /*match self.map.entry(root_key) {
            Entry::Occupied(e) => match &e.get().next_key {
                Some(next_key) => todo!(),
                None => (),
            },
            Entry::Vacant(_) => (),
        }*/

        if let Entry::Occupied(root_entry) = self.map.entry(root_key) {
            let mut curr_entry = root_entry;

            while let Some(next_key) = curr_entry.get_mut().next_key.take() {
                //self.roots[root_index] =
                curr_entry.remove_entry();
                curr_entry = match self.map.entry(next_key) {
                    Entry::Occupied(e) => e,
                    Entry::Vacant(_) => {
                        return Err(Error::KeyError("Key not found".to_string()));
                    }
                }
            }
        } else {
            return Err(Error::KeyError("Root key not found".to_string()));
        }

        todo!()

        /*if let Some(root_entry) = self.map.entry(root_key) {
            /*let mut curr_entry = root_entry;
            while let Some(next_key) = curr_entry.next_key.as_ref() {
                match self.get_link_entry(next_key) {
                    Some(entry) => {
                        curr_entry = entry;
                    }
                    None => return Err(Error::KeyError("Key not found".to_string())),
                }
            }
            // curr_entry is the last entry in the chain
            self.roots[root_index] = root_key.clone();*/
            Ok(())
        } else {
            Err(Error::KeyError("Root key not found".to_string()))
        }*/
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
    assert_eq!(res.len(), lhm.map.len());

    let res: Vec<_> = lhm.iter_link(&1).collect();
    assert_eq!(res, vec!["key1", "key11", "key111"]);

    Ok(())
}
