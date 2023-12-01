use std::{
    borrow::Borrow,
    collections::{
        hash_map::{Entry, OccupiedEntry, VacantEntry},
        HashMap, HashSet, LinkedList,
    },
    fmt::Debug,
    hash::Hash,
    iter,
};

/// a `VersionedMap` stores linked lists.
#[derive(Default, Debug, PartialEq, Eq)]
pub struct RevisionMap<K, V>
where
    K: Debug + PartialEq + Eq + Hash,
    V: Debug,
{
    pub(crate) map: HashMap<K, LinkedList<V>>,
    length: usize,
}

impl<K, V> RevisionMap<K, V>
where
    K: Hash + PartialEq + Eq + Clone + Debug,
    V: Clone + Debug,
{
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
            length: 0,
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            map: HashMap::with_capacity(capacity),
            length: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    pub fn nb_chains(&self) -> usize {
        self.map.len()
    }

    pub fn chain_length(&self, key: &K) -> Option<usize> {
        self.map.get(key).map(|chain| chain.len())
    }

    fn insert_new_chain(entry: VacantEntry<K, LinkedList<V>>, value: V) {
        let mut new_chain = LinkedList::new();
        new_chain.push_front(value);
        entry.insert(new_chain);
    }

    fn insert_in_chain(mut entry: OccupiedEntry<K, LinkedList<V>>, value: V) {
        let chain = entry.get_mut();
        chain.push_front(value);
    }

    /// Inserts value at the front of the chain for a given key
    pub fn insert(&mut self, key: K, value: V) {
        // All branches will add an element in the map.
        self.length += 1;

        match self.map.entry(key) {
            Entry::Occupied(entry) => Self::insert_in_chain(entry, value),
            Entry::Vacant(entry) => Self::insert_new_chain(entry, value),
        }
    }

    /// Returns the last revised value for a given key.
    pub fn get_current_revision<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.get(key).and_then(|chain| chain.front())
    }

    /// Returns a mutable reference to the last revised value for a given key.
    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.get_mut(key).and_then(|chain| chain.front_mut())
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }

    /// Iterates through all keys in arbitrary order.
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.map.keys()
    }

    /// Iterates through all revisions of all keys.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.map
            .iter()
            .flat_map(|(k, chain)| chain.iter().map(move |v| (k, v)))
    }

    /// Iterates through all revisions of a given key starting with the more
    /// recent one.
    pub fn iter_chain<'a, Q>(&'a self, key: &Q) -> Box<dyn 'a + Iterator<Item = &V>>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        match self.map.get(key) {
            Some(chain) => Box::new(chain.iter()),
            None => Box::new(iter::empty()),
        }
    }

    /// Removes and returns an iterator over all revisions from a given key.
    pub fn remove_chain<'a, Q>(&'a mut self, key: &Q) -> Box<dyn 'a + Iterator<Item = V>>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        match self.map.remove(key) {
            Some(chain) => {
                self.length -= chain.len();
                Box::new(chain.into_iter())
            }
            None => Box::new(iter::empty()),
        }
    }

    /// Removes and returns the older revision from a given key.
    pub fn remove_older_revision(&mut self, key: &K) -> Option<V> {
        let Entry::Occupied(mut entry) = self.map.entry(key.clone()) else {
            return None;
        };
        let chain = entry.get_mut();
        let removed_entry = chain.pop_back();

        // remove linked list if the last revision was removed
        if chain.is_empty() {
            entry.remove_entry();
        }

        // update map length
        if removed_entry.is_some() {
            self.length -= 1;
        }

        removed_entry
    }

    pub fn retain_keys(&mut self, keys: HashSet<&K>) {
        let inner_keys: Vec<K> = self.keys().cloned().collect();
        for key in inner_keys {
            if !keys.contains(&key) {
                let _ = self.remove_chain(&key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn test_revision_map() {
        let mut map: RevisionMap<String, String> = RevisionMap::new();
        assert!(map.is_empty());

        // Insertions
        map.insert("Part1".to_string(), "Rotation1".to_string());
        assert_eq!(map.map.len(), 1);
        map.insert("Part1".to_string(), "Rotation2".to_string());
        assert_eq!(map.len(), 2);
        // the inner map only has 1 entry with 2 revisions
        assert_eq!(map.map.len(), 1);

        map.insert("Part2".to_string(), "New".to_string());
        assert_eq!(map.map.len(), 2);

        // Get
        assert_eq!(map.get_current_revision("Part1").unwrap(), "Rotation2");
        assert_eq!(map.get_current_revision("Part2").unwrap(), "New");
        assert!(map.get_current_revision("Missing").is_none());

        // Iterators
        let vec: Vec<_> = map.iter().collect();
        assert_eq!(vec.len(), 3);

        let vec: Vec<_> = map.iter_chain("Part1").collect();
        assert_eq!(vec, vec!["Rotation2", "Rotation1"]);

        let keys_set = map.keys().collect::<HashSet<_>>();
        assert!(keys_set.contains(&"Part1".to_string()));
        assert!(keys_set.contains(&"Part2".to_string()));

        // Remove values
        assert_eq!(
            map.remove_older_revision(&"Part2".to_string()).unwrap(),
            "New"
        );
        assert_eq!(map.len(), 2);
        assert_eq!(map.map.len(), 1);

        let vec: Vec<_> = map.remove_chain("Part1").collect();
        assert_eq!(vec, vec!["Rotation2".to_string(), "Rotation1".to_string()]);
        assert!(map.is_empty());
    }
}
