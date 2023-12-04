use std::{
    borrow::Borrow,
    collections::{
        hash_map::{Entry, OccupiedEntry, VacantEntry},
        HashMap, HashSet, LinkedList,
    },
    fmt::Debug,
    hash::Hash,
};

/// a `VersionedMap` stores linked lists.
#[derive(Default, Debug, PartialEq, Eq)]
pub struct RevisionMap<K, V>
where
    K: Debug + PartialEq + Eq + Hash,
    V: Debug,
{
    pub(crate) map: HashMap<K, LinkedList<V>>,
}

impl<K, V> RevisionMap<K, V>
where
    K: Hash + PartialEq + Eq + Clone + Debug,
    V: Clone + Debug,
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
        self.map.values().map(|chain| chain.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
    pub fn iter_chain<Q>(&self, key: &Q) -> Option<impl Iterator<Item = &V>>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.get(key).map(LinkedList::iter)
    }

    /// Removes and returns an iterator over all revisions from a given key.
    pub fn remove_chain<Q>(&mut self, key: &Q) -> Option<impl Iterator<Item = V>>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.remove(key).map(LinkedList::into_iter)
    }

    /// Removes and returns the older revisions from a given key.
    pub fn pop_tail<Q>(&mut self, key: &Q) -> Option<impl Iterator<Item = V>>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map
            .get_mut(key)
            .map(|chain| chain.split_off(1).into_iter())
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
        map.insert("Part1".to_string(), "Part1V1".to_string());
        assert_eq!(map.map.len(), 1);
        map.insert("Part1".to_string(), "Part1V2".to_string());
        assert_eq!(map.len(), 2);
        // the inner map only has 1 entry with 2 revisions
        assert_eq!(map.map.len(), 1);

        map.insert("Part2".to_string(), "Part2V1".to_string());
        map.insert("Part2".to_string(), "Part2V2".to_string());
        map.insert("Part2".to_string(), "Part2V3".to_string());
        assert_eq!(map.map.len(), 2);
        assert_eq!(map.len(), 5);

        // Get
        assert_eq!(map.get_current_revision("Part1").unwrap(), "Part1V2");
        assert_eq!(map.get_current_revision("Part2").unwrap(), "Part2V3");
        assert!(map.get_current_revision("Missing").is_none());

        // Iterators
        let vec: Vec<_> = map.iter().collect();
        assert_eq!(vec.len(), map.len());

        let vec: Vec<_> = map.iter_chain("Part1").unwrap().collect();
        assert_eq!(vec, vec!["Part1V2", "Part1V1"]);

        let keys_set = map.keys().collect::<HashSet<_>>();
        assert!(keys_set.contains(&"Part1".to_string()));
        assert!(keys_set.contains(&"Part2".to_string()));

        // Remove values
        let vec: Vec<_> = map.remove_chain("Part1").unwrap().collect();
        assert_eq!(vec, vec!["Part1V2".to_string(), "Part1V1".to_string()]);
        assert_eq!(map.len(), 3);
        assert_eq!(map.map.len(), 1);

        // Pop tail
        let vec: Vec<_> = map.pop_tail("Part2").unwrap().collect();
        assert_eq!(vec, vec!["Part2V2".to_string(), "Part2V1".to_string()]);
        assert_eq!(map.len(), 1);
        let vec: Vec<_> = map.remove_chain("Part2").unwrap().collect();
        assert_eq!(vec, vec!["Part2V3".to_string()]);

        assert!(map.is_empty());
    }
}
