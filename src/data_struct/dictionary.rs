use std::{
    borrow::Borrow,
    collections::{hash_map::Entry, HashMap},
    fmt::{self, Debug},
    hash::Hash,
    marker::PhantomData,
    mem::swap,
};

use serde::{
    de::{MapAccess, Visitor},
    ser::SerializeMap,
    Deserialize, Deserializer, Serialize,
};

use super::error::Error;

type Index = usize;
/// `HashMap` keeping insertion order inspired by Python dictionary.
#[derive(Default, Clone, Eq, PartialEq, Debug)]
pub struct Dict<K, V>
where
    K: Hash + PartialEq + Eq + Clone + Debug,
{
    indices: HashMap<K, Index>,
    entries: Vec<(K, V)>,
}

impl<K, V> Dict<K, V>
where
    K: Hash + PartialEq + Eq + Clone + Debug,
{
    #[must_use]
    pub fn new() -> Self {
        Self {
            indices: HashMap::new(),
            entries: Vec::new(),
        }
    }

    #[must_use]
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
        match self.indices.entry(key.clone()) {
            Entry::Occupied(e) => {
                // replace existing entry value in vector
                Some(std::mem::replace(&mut self.entries[*e.get()].1, value))
            }
            Entry::Vacant(e) => {
                let new_index = self.entries.len();
                self.entries.push((key, value));
                e.insert(new_index);
                None
            }
        }
    }

    /// Removes the entry corresponding to the given key.
    /// To maintain order, all inserted entries after the removed one will be
    /// shifted by one and the indices map will be updated accordingly.
    /// Compared to a regular `HashMap`, this operation is O(n).
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let entry_index = self.indices.remove(key)?;

        self.indices
            .iter_mut()
            .filter(|(_, index)| **index > entry_index)
            .for_each(|(_, index)| *index -= 1);

        Some(self.entries.remove(entry_index).1)
    }

    /// Updates the key for a given entry while retaining the current order.
    pub fn update_key(&mut self, old_key: &K, mut new_key: K) -> Result<(), Error> {
        // Get index from old_key
        let index_entry = *self
            .indices
            .get(old_key)
            .ok_or(Error::missing_entry(old_key))?;

        match self.indices.entry(new_key.clone()) {
            Entry::Occupied(e) => Err(Error::existing_entry(e.key())),
            Entry::Vacant(e) => {
                // Insert new key inside indices
                e.insert(index_entry);
                // Remove old key from indices
                let _ = self.indices.remove(old_key);
                // Replace old_key with new_key inside entries
                swap(&mut self.entries[index_entry].0, &mut new_key);
                Ok(())
            }
        }
    }

    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.indices.contains_key(key)
    }

    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let entry_index = self.indices.get(key)?;
        self.entries.get(*entry_index).map(|(_, v)| v)
    }

    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let entry_index = self.indices.get(key)?;
        self.entries.get_mut(*entry_index).map(|(_, v)| v)
    }

    pub fn get_key_value<Q>(&self, key: &Q) -> Option<(&K, &V)>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let entry_index = self.indices.get(key)?;
        let (key, value) = self.entries.get(*entry_index)?;
        Some((key, value))
    }

    /// Returns an iterator over keys and values in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.entries.iter().map(|(k, v)| (k, v))
    }

    /// Returns an iterator over values in insertion order
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.entries.iter().map(|(_, v)| v)
    }

    /// Returns an iterator over keys in insertion order.
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.entries.iter().map(|(k, _)| k)
    }
}

impl<K, V> IntoIterator for Dict<K, V>
where
    K: Hash + PartialEq + Eq + Clone + Debug,
{
    type IntoIter = std::vec::IntoIter<(K, V)>;
    type Item = (K, V);

    /// Returns an iterator over keys and values in insertion order.
    fn into_iter(self) -> Self::IntoIter {
        self.entries.into_iter()
    }
}

impl<K, V> FromIterator<(K, V)> for Dict<K, V>
where
    K: Hash + PartialEq + Eq + Clone + Debug,
{
    fn from_iter<T: IntoIterator<Item = (K, V)>>(iter: T) -> Self {
        let iterator = iter.into_iter();
        let mut dict = Self::with_capacity(iterator.size_hint().0);
        for (key, value) in iterator {
            dict.insert(key, value);
        }
        dict
    }
}

impl<K, V> Serialize for Dict<K, V>
where
    K: Hash + PartialEq + Eq + Clone + Debug + Serialize,
    V: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.len()))?;
        for (k, v) in self.iter() {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

struct DictVisitor<K, V>
where
    K: Hash + PartialEq + Eq + Clone + Debug,
{
    marker: PhantomData<fn() -> Dict<K, V>>,
}

impl<K, V> DictVisitor<K, V>
where
    K: Hash + PartialEq + Eq + Clone + Debug,
{
    fn new() -> Self {
        Self {
            marker: PhantomData,
        }
    }
}

impl<'de, K, V> Visitor<'de> for DictVisitor<K, V>
where
    K: Hash + PartialEq + Eq + Clone + Debug + Deserialize<'de>,
    V: Deserialize<'de>,
{
    type Value = Dict<K, V>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a Dict")
    }

    // Create a `Dict` from an abstract map provided by the Deserializer.
    // This abstract map should preserve the item's order during the
    // deserialization.
    fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut map = Dict::with_capacity(access.size_hint().unwrap_or(0));

        while let Some((key, value)) = access.next_entry()? {
            map.insert(key, value);
        }

        Ok(map)
    }
}

impl<'de, K, V> Deserialize<'de> for Dict<K, V>
where
    K: Hash + PartialEq + Eq + Clone + Debug + Deserialize<'de>,
    V: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(DictVisitor::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dict() -> Result<(), Error> {
        let mut d: Dict<String, String> = Dict::new();
        assert!(d.is_empty());

        // Insertions
        d.insert("ID1".to_string(), "Foo".to_string());
        d.insert("ID2".to_string(), "Bar".to_string());
        d.insert("ID3".to_string(), "Baz".to_string());
        assert_eq!(d.len(), 3);

        // Get
        assert_eq!(
            d.get_key_value("ID2").unwrap(),
            (&"ID2".to_string(), &"Bar".to_string())
        );

        // Edit
        // Overwrite value without changing order
        d.insert("ID1".to_string(), "Foox".to_string());

        // Update key without changing order
        d.update_key(&"ID2".to_string(), "ID2_bis".to_string())?;
        assert!(d.get_key_value(&String::from("ID2")).is_none());
        assert_eq!(
            d.get_key_value(&"ID2_bis".to_string()).unwrap(),
            (&"ID2_bis".to_string(), &"Bar".to_string())
        );

        // Update key error cases
        // missing old key
        assert!(d.update_key(&"Bad".to_string(), "New".to_string()).is_err());
        // existing new key
        assert!(d.update_key(&"ID1".to_string(), "ID3".to_string()).is_err());

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

    #[test]
    fn test_dict_serialization() {
        // Init dict
        let mut d: Dict<String, String> = Dict::new();
        d.insert("ID1".to_string(), "Foo".to_string());
        d.insert("ID2".to_string(), "Bar".to_string());
        d.insert("ID3".to_string(), "Baz".to_string());
        d.remove(&"ID2".to_string());
        d.insert("ID4".to_string(), "Bar2".to_string());

        // serialize
        let data = serde_json::to_vec(&d).unwrap();

        // can be read as a hashmap but this the order will be lost
        let map: HashMap<String, String> = serde_json::from_slice(&data).unwrap();
        assert_eq!(map.len(), d.len());
        assert!(map.contains_key("ID1"));
        assert!(map.contains_key("ID3"));
        assert!(map.contains_key("ID4"));

        // deserialization as dict will keep the order
        let d2: Dict<String, String> = serde_json::from_slice(&data).unwrap();
        assert_eq!(d2.len(), d.len());
        assert_eq!(d2.iter().collect::<Vec<_>>(), d.iter().collect::<Vec<_>>());
    }
}
