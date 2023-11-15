use std::{
    collections::{hash_map::Entry, HashMap},
    fmt::Debug,
    hash::Hash,
    usize,
};

use super::error::Error;

type Index = usize;
/// HashMap keeping insertion order inspired by Python dictionary.
/// Contrary to the Python one, this implementation does not store a duplicate
/// of the key in the entries.
#[derive(Default)]
pub struct Dict<K, V> {
    indices: HashMap<K, Index>,
    entries: Vec<V>,
}

impl<K, V> Dict<K, V>
where
    K: Hash + PartialEq + Eq + Clone + Debug,
{
    pub fn new() -> Self {
        Self {
            indices: HashMap::new(),
            entries: Vec::new(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            indices: HashMap::with_capacity(capacity),
            entries: Vec::with_capacity(capacity),
        }
    }

    pub fn len(&self) -> usize {
        self.indices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Inserts a new entry with a given key.
    /// If a given key already exists, the entry will be overwritten without
    /// changing the order.
    /// Otherwise, new entries are simply pushed at the end.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        match self.indices.entry(key) {
            Entry::Occupied(e) => {
                // replace existing entry in vector
                Some(std::mem::replace(&mut self.entries[*e.get()], value))
            }
            Entry::Vacant(e) => {
                let new_index = self.entries.len();
                self.entries.push(value);
                e.insert(new_index);
                None
            }
        }
    }

    /// Removes the entry corresponding to the given key.
    /// To maintain order, all inserted entries after the removed one will be
    /// shifted by one and the indices map will be updated accordingly.
    /// Compared to a regular HashMap, this operation is O(n).
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let entry_index = self.indices.remove(key)?;

        // shift indices over entry_index by one
        self.indices
            .iter_mut()
            .filter(|(_, index)| **index > entry_index)
            .for_each(|(_, index)| *index -= 1);

        // replace vec entry with None
        Some(self.entries.remove(entry_index))
    }

    /// Updates the key for a given entry while retaining the current order.
    pub fn update_key(&mut self, old_key: &K, new_key: K) -> Result<(), Error> {
        let index_entry = self
            .indices
            .remove(old_key)
            .ok_or(Error::missing_entry(old_key))?;

        match self.indices.entry(new_key) {
            Entry::Occupied(e) => Err(Error::existing_entry(e.key())),
            Entry::Vacant(e) => {
                e.insert(index_entry);
                Ok(())
            }
        }
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        let entry_index = self.indices.get(key)?;
        self.entries.get(*entry_index)
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        let entry_index = self.indices.get(key)?;
        self.entries.get_mut(*entry_index)
    }

    pub fn get_key_value(&self, key: &K) -> Option<(&K, &V)> {
        let (key, entry_index) = self.indices.get_key_value(key)?;
        let value = self.entries.get(*entry_index)?;
        Some((key, value))
    }

    /// Returns an iterator over values in insertion order
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.entries.iter()
    }

    /// Returns an iterator over keys and values in insertion order.
    /// This function allocates a temporary vector to sort the keys.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        let mut tmp_vec: Vec<_> = self.indices.iter().collect();
        // Key's indexes correspond to insertion order.
        tmp_vec.sort_unstable_by_key(|(_, index)| *index);

        tmp_vec
            .into_iter()
            .map(|(key, index)| (key, &self.entries[*index]))
    }
}

#[test]
fn test_dict() -> Result<(), Error> {
    let mut d: Dict<String, String> = Dict::new();
    assert!(d.is_empty());

    // Insertions
    d.insert(String::from("ID1"), String::from("Foo"));
    d.insert(String::from("ID2"), String::from("Bar"));
    d.insert(String::from("ID3"), String::from("Baz"));
    assert_eq!(d.len(), 3);

    // Get
    assert_eq!(
        d.get_key_value(&String::from("ID2")).unwrap(),
        (&String::from("ID2"), &String::from("Bar"))
    );

    // Edit
    // Overwrite value without changing order
    d.insert("ID1".to_string(), "Foox".to_string());

    // Update key without changing order
    d.update_key(&String::from("ID2"), String::from("ID2_bis"))?;
    assert!(d.get_key_value(&String::from("ID2")).is_none());
    assert_eq!(
        d.get_key_value(&String::from("ID2_bis")).unwrap(),
        (&String::from("ID2_bis"), &String::from("Bar"))
    );

    // Iterators
    assert_eq!(d.values().collect::<Vec<_>>(), vec!["Foox", "Bar", "Baz"]);

    assert_eq!(
        d.iter().collect::<Vec<_>>(),
        vec![
            (&String::from("ID1"), &String::from("Foox")),
            (&String::from("ID2_bis"), &String::from("Bar")),
            (&String::from("ID3"), &String::from("Baz")),
        ]
    );

    // Remove
    assert!(d.remove(&String::from("Missing")).is_none());
    assert_eq!(d.remove(&String::from("ID2_bis")), Some("Bar".to_string()));
    assert_eq!(d.len(), 2);

    // Check order is maintained
    assert_eq!(d.values().collect::<Vec<_>>(), vec!["Foox", "Baz"]);

    // Insertion after remove
    d.insert(String::from("ID4"), String::from("Test"));
    assert_eq!(d.values().collect::<Vec<_>>(), vec!["Foox", "Baz", "Test"]);

    Ok(())
}
