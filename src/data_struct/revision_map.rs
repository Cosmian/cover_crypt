use std::{
    borrow::Borrow,
    collections::{
        hash_map::{Entry, OccupiedEntry, VacantEntry},
        HashMap, LinkedList,
    },
    fmt::Debug,
    hash::Hash,
};

/// a `RevisionMap` stores linked lists indexed by given keys.
/// The element inside the linked list are stored in reverse insertion order
/// while the keys are stored in arbitrary order.
///
/// Map {
///     key2: b
///     key1: a" -> a' > a
///     key3: c' -> c
/// }
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
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            map: HashMap::with_capacity(capacity),
        }
    }

    /// Returns the number of chains stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Returns the total number of elements stored.
    pub fn count_elements(&self) -> usize {
        self.map.values().map(LinkedList::len).sum()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn chain_length(&self, key: &K) -> Option<usize> {
        self.map.get(key).map(LinkedList::len)
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
        self.map.get(key).and_then(LinkedList::front)
    }

    /// Returns a mutable reference to the last revised value for a given key.
    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.get_mut(key).and_then(LinkedList::front_mut)
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }

    /// Iterates through all keys in arbitrary order.
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.map.keys()
    }

    /// Iterates through all revisions of all keys.
    pub fn flat_iter(&self) -> impl Iterator<Item = (&K, &V)> {
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

    /// Retains only the elements with a key validating the given predicate.
    pub fn retain(&mut self, f: impl Fn(&K) -> bool) {
        self.map.retain(|key, _| f(key));
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
        assert_eq!(map.count_elements(), 1);
        assert_eq!(map.len(), 1);
        map.insert("Part1".to_string(), "Part1V2".to_string());
        assert_eq!(map.count_elements(), 2);
        // two elements in the same chain
        assert_eq!(map.len(), 1);

        map.insert("Part2".to_string(), "Part2V1".to_string());
        map.insert("Part2".to_string(), "Part2V2".to_string());
        map.insert("Part2".to_string(), "Part2V3".to_string());
        assert_eq!(map.len(), 2);
        assert_eq!(map.count_elements(), 5);

        map.insert("Part3".to_string(), "Part3V1".to_string());
        assert_eq!(map.count_elements(), 6);

        // Get
        assert_eq!(map.get_current_revision("Part1").unwrap(), "Part1V2");
        assert_eq!(map.get_current_revision("Part2").unwrap(), "Part2V3");
        assert!(map.get_current_revision("Missing").is_none());

        // Iterators
        let vec: Vec<_> = map.flat_iter().collect();
        assert_eq!(vec.len(), map.count_elements());

        let vec: Vec<_> = map.iter_chain("Part1").unwrap().collect();
        assert_eq!(vec, vec!["Part1V2", "Part1V1"]);

        let keys_set = map.keys().collect::<HashSet<_>>();
        assert!(keys_set.contains(&"Part1".to_string()));
        assert!(keys_set.contains(&"Part2".to_string()));

        // Remove values
        let vec: Vec<_> = map.remove_chain("Part1").unwrap().collect();
        assert_eq!(vec, vec!["Part1V2".to_string(), "Part1V1".to_string()]);
        assert_eq!(map.count_elements(), 4);
        assert_eq!(map.len(), 2);

        // Pop tail
        let vec: Vec<_> = map.pop_tail("Part2").unwrap().collect();
        assert_eq!(vec, vec!["Part2V2".to_string(), "Part2V1".to_string()]);
        assert_eq!(map.count_elements(), 2);
        let vec: Vec<_> = map.remove_chain("Part2").unwrap().collect();
        assert_eq!(vec, vec!["Part2V3".to_string()]);
        // Empty pop tail
        assert!(map.pop_tail("Part3").unwrap().next().is_none());

        // Retain
        map.retain(|_| true);
        assert_eq!(map.count_elements(), 1);
        map.retain(|_| false);
        assert!(map.is_empty());
    }
}
