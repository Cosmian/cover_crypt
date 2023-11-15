use std::{
    collections::{hash_map::Entry, HashMap, LinkedList},
    fmt::Debug,
    hash::Hash,
    usize,
};

use super::error::Error;

type Index = usize;
/// Custom implementation based on Python dictionary.
/// Hashmap keeping insertion order.
/// This implementation does not store a duplicate of the key in the entries.
#[derive(Default)]
pub struct Dict<K, V> {
    indices: HashMap<K, Index>,
    entries: InnerVec<V>,
}

#[derive(Default)]
struct InnerVec<V> {
    data: Vec<Option<V>>,
    free_indices: LinkedList<Index>,
}

impl<K, V> Dict<K, V>
where
    K: Hash + PartialEq + Eq + Clone + Debug,
{
    pub fn new() -> Self {
        Self {
            indices: HashMap::new(),
            entries: InnerVec {
                data: Vec::new(),
                free_indices: LinkedList::new(),
            },
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            indices: HashMap::with_capacity(capacity),
            entries: InnerVec {
                data: Vec::with_capacity(capacity),
                free_indices: LinkedList::new(),
            },
        }
    }

    pub fn len(&self) -> usize {
        self.indices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Private function to insert a new entry in the vector unfilled positions
    /// or at the end if full.
    fn insert_entry(entries: &mut InnerVec<V>, value: V) -> Index {
        if let Some(free_index) = entries.free_indices.pop_front() {
            debug_assert!(entries.data[free_index].is_none());
            let _ = std::mem::replace(&mut entries.data[free_index], Some(value));
            free_index
        } else {
            let new_index = entries.data.len();
            entries.data.push(Some(value));
            new_index
        }
    }

    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        match self.indices.entry(key) {
            Entry::Occupied(e) => {
                // replace existing entry in vector
                std::mem::replace(&mut self.entries.data[*e.get()], Some(value))
            }
            Entry::Vacant(e) => {
                e.insert(Self::insert_entry(&mut self.entries, value));
                None
            }
        }
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        let entry_index = self.indices.remove(key)?;

        // add free index to our pool
        self.entries.free_indices.push_back(entry_index);

        // replace vec entry with None
        self.entries.data.get_mut(entry_index)?.take()
    }

    /// Updates the key for a given entry while retaining the given entry order
    /// in the Vec.
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
        self.entries.data.get(*entry_index)?.as_ref()
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        let entry_index = self.indices.get(key)?;
        self.entries.data.get_mut(*entry_index)?.as_mut()
    }

    pub fn get_key_value(&self, key: &K) -> Option<(&K, &V)> {
        let (key, entry_index) = self.indices.get_key_value(key)?;
        let value = self.entries.data.get(*entry_index)?.as_ref()?;
        Some((key, value))
    }

    /// Returns an iterator over values in insertion order
    pub fn values(&self) -> impl Iterator<Item = &V> {
        // Skip unfilled vector entry
        self.entries.data.iter().filter_map(|entry| entry.as_ref())
    }

    /// Returns an iterator over keys and values in insertion order.
    /// This function allocates a temporary vector to sort the keys.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        let mut tmp_vec: Vec<_> = self.indices.iter().collect();
        // Key's indexes correspond to insertion order,
        // no two key can map to the same index.
        tmp_vec.sort_unstable_by_key(|(_, index)| *index);

        tmp_vec.into_iter().map(|(key, index)| {
            (
                key,
                self.entries.data[*index]
                    .as_ref()
                    .expect("A dictionary key entry must have a corresponding value"),
            )
        })
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
    d.update_key(&String::from("ID2"), String::from("ID2_bis"))?;
    assert!(d.get_key_value(&String::from("ID2")).is_none());
    assert_eq!(
        d.get_key_value(&String::from("ID2_bis")).unwrap(),
        (&String::from("ID2_bis"), &String::from("Bar"))
    );

    // Iterators
    assert_eq!(d.values().collect::<Vec<_>>(), vec!["Foo", "Bar", "Baz"]);

    assert_eq!(
        d.iter().collect::<Vec<_>>(),
        vec![
            (&String::from("ID1"), &String::from("Foo")),
            (&String::from("ID2_bis"), &String::from("Bar")),
            (&String::from("ID3"), &String::from("Baz")),
        ]
    );

    // Remove
    assert!(d.remove(&String::from("Missing")).is_none());
    assert_eq!(d.remove(&String::from("ID2_bis")), Some("Bar".to_string()));
    assert_eq!(d.len(), 2);

    // Check order is maintained
    assert_eq!(d.values().collect::<Vec<_>>(), vec!["Foo", "Baz"]);

    // Insertion in free index
    assert_eq!(d.entries.free_indices.len(), 1);
    d.insert(String::from("ID4"), String::from("Test"));
    assert_eq!(d.values().collect::<Vec<_>>(), vec!["Foo", "Baz", "Test"]);

    Ok(())
}
