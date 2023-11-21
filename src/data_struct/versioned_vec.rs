use std::{
    collections::{linked_list, LinkedList},
    iter,
};

use serde::{Deserialize, Serialize};

use super::error::Error;

/// a `VersionedVec` stores for each entry a linked list of versions.
/// The entry versions are stored in reverse chronological order:
///
/// Vec [
///     0: a" -> a' -> a
///     1: b
///     2: c' -> c
/// ]
///
/// Insertions are only allowed at the front of the linked list.
/// Deletions can only happen at the end of the linked list.
///
/// This guarantees that the entry versions are always ordered.
// TODO: does index matter for Eq compare?
// TODO: check Serialize/Deserialize
#[derive(Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionedVec<T> {
    data: Vec<LinkedList<T>>,
    length: usize,
}

impl<T> VersionedVec<T> {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            length: 0,
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            length: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn push_front(&mut self, chain_index: usize, item: T) -> Result<(), Error> {
        let chain = self
            .data
            .get_mut(chain_index)
            .ok_or(Error::missing_entry(&chain_index))?;

        self.length += 1;
        chain.push_front(item);
        Ok(())
    }

    /// Inserts entry versions in reverse chronological order
    /// The iterator must be in chronological order as the items are inserted
    /// backward.
    pub fn insert_new_chain(&mut self, iterator: impl Iterator<Item = T>) {
        let mut new_list = LinkedList::new();
        for item in iterator {
            new_list.push_front(item);
        }
        if !new_list.is_empty() {
            self.length += new_list.len();
            self.data.push(new_list);
        }
    }

    /// Removes old entry versions.
    /*pub fn pop_chain(&mut self, chain_index: usize, stop_key: &K) -> Result<(), Error> {
        let list = &mut self.data[chain_index];

        while let Some((key, _)) = list.back() {
            if key == stop_key {
                return Ok(());
            }
            list.pop_back();
        }
        Err(Error::KeyError("Stop key was not found".to_string()))
    }*/

    /// Removes old entry version.
    pub fn pop_back(&mut self, chain_index: usize) -> Result<T, Error> {
        let chain = self
            .data
            .get_mut(chain_index)
            .ok_or(Error::missing_entry(&chain_index))?;

        let removed_item = chain.pop_back().expect("chains should not be empty");
        self.length -= 1;

        if chain.is_empty() {
            self.data.swap_remove(chain_index);
        }

        Ok(removed_item)
    }

    /// Provides reference to the oldest entry version.
    pub fn back(&self, chain_index: usize) -> Option<&T> {
        self.data.get(chain_index)?.back()
    }

    /// Provides reference to the current entry version.
    pub fn front(&self, chain_index: usize) -> Option<&T> {
        self.data.get(chain_index)?.front()
    }

    /// Iterates through all versions of an entry starting from the most recent
    /// one.
    pub fn iter_chain(&self, chain_index: usize) -> impl Iterator<Item = &T> {
        self.data[chain_index].iter()
    }

    /// Iterates through all versions of all entries
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.data.iter().flat_map(|chain| chain.iter())
    }

    pub fn bfs(&self) -> BfsIterator<T> {
        BfsIterator::new(self)
    }
}

pub struct BfsIterator<'a, T> {
    chains: Vec<linked_list::Iter<'a, T>>,
    index: usize,
}

impl<'a, T> BfsIterator<'a, T> {
    pub fn new(versioned_vec: &'a VersionedVec<T>) -> Self {
        Self {
            chains: versioned_vec.data.iter().map(LinkedList::iter).collect(),
            index: 0,
        }
    }
}

impl<'a, T> Iterator for BfsIterator<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.chains.is_empty() {
                return None;
            }
            self.index %= self.chains.len();
            let chain = &mut self.chains[self.index];

            if let Some(next_entry) = chain.next() {
                self.index += 1;
                break Some(next_entry);
            } else {
                let _ = self.chains.remove(self.index);
            }
        }
    }
}

/// Create VersionedVec from an iterator, each element will be inserted in a
/// different chain. Use `insert_new_chain` to collect an iterator inside the
/// same chain.
impl<T> FromIterator<T> for VersionedVec<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let iterator = iter.into_iter();
        let mut vec = Self::with_capacity(iterator.size_hint().0);
        for item in iterator {
            vec.insert_new_chain(iter::once(item))
        }
        vec
    }
}

#[test]
fn test_versioned_vec() -> Result<(), Error> {
    let mut versioned_vec: VersionedVec<(u32, String)> = VersionedVec::new();
    assert!(versioned_vec.is_empty());

    // Inserting new chains
    let first_chain_index = 0;
    versioned_vec.insert_new_chain(
        vec![
            (1, "key1".to_string()),
            (11, "key11".to_string()),
            (111, "key111".to_string()),
        ]
        .into_iter(),
    );
    let second_chain_index = 1;
    versioned_vec
        .insert_new_chain(vec![(2, "key2".to_string()), (22, "key22".to_string())].into_iter());
    let third_chain_index = 2;
    versioned_vec.insert_new_chain(vec![(3, "key3".to_string())].into_iter());

    assert_eq!(versioned_vec.data.len(), 3);
    assert_eq!(versioned_vec.len(), 6);

    // Get front
    assert_eq!(
        versioned_vec.front(second_chain_index),
        Some(&(22, "key22".to_string()))
    );

    // Push back
    let new_entry_version = (222, "key222".to_string());
    versioned_vec.push_front(second_chain_index, new_entry_version.clone())?;

    assert_eq!(
        versioned_vec.front(second_chain_index),
        Some(&new_entry_version)
    );

    // Remove elements
    versioned_vec.pop_back(first_chain_index)?;
    assert_eq!(versioned_vec.len(), 6);

    versioned_vec.pop_back(second_chain_index)?;
    assert_eq!(versioned_vec.len(), 5);
    // Front element should be the same
    assert_eq!(
        versioned_vec.front(second_chain_index),
        Some(&new_entry_version)
    );

    versioned_vec.pop_back(third_chain_index)?;
    assert_eq!(versioned_vec.len(), 4);
    // the chain 3 was completely removed
    assert!(versioned_vec.pop_back(third_chain_index).is_err());

    // Iterate
    assert_eq!(versioned_vec.iter_chain(first_chain_index).count(), 2);
    assert_eq!(versioned_vec.iter().count(), versioned_vec.len());

    Ok(())
}

#[test]
fn test_versioned_vec_iterator() {
    let mut versioned_vec: VersionedVec<u32> = VersionedVec::new();

    // Inserting new chains
    versioned_vec.insert_new_chain(vec![1, 11, 111].into_iter());
    versioned_vec.insert_new_chain(vec![2, 22].into_iter());
    versioned_vec.insert_new_chain(vec![3].into_iter());

    // Depth iter
    let depth_iter: Vec<_> = versioned_vec.iter().copied().collect();
    assert_eq!(depth_iter, vec![111, 11, 1, 22, 2, 3]);

    // Breadth iter
    let bfs: Vec<_> = versioned_vec.bfs().copied().collect();
    assert_eq!(bfs, vec![111, 22, 3, 11, 2, 1]);

    // Iter chain by chain <=> depth iter
    assert_eq!(
        versioned_vec.iter().collect::<Vec<_>>(),
        (0..3)
            .flat_map(|index| versioned_vec.iter_chain(index))
            .collect::<Vec<_>>()
    );
}
