use std::collections::LinkedList;

use crate::Error;

/// a `VersionedVec` stores for each entry a linked list of versions.
/// The entry versions are stored in reverse chronological order:
///
/// Vec [
///     0: a'' -> a' -> a
///     1: b
///     2: c' -> c
/// ]
///
/// Insertions are only allowed at the front of the linked list.
/// Deletions can only happen at the end of the linked list.
///
/// This guarantees that the entry versions are always ordered.
#[derive(Default)]
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
        //self.data.iter().map(|list| list.len()).sum()
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Inserts entry versions in reverse chronological order
    /// The iterator must be in chronological order as the items are inserted
    /// backward.
    pub fn insert_new_chain(&mut self, iterator: impl Iterator<Item = T>) -> Result<(), Error> {
        let mut new_list = LinkedList::new();
        for item in iterator {
            new_list.push_front(item);
        }

        self.length += new_list.len();
        self.data.push(new_list);

        Ok(())
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
    pub fn pop_back(&mut self, chain_index: usize) -> Option<T> {
        // TODO: update len
        self.data.get_mut(chain_index)?.pop_back()
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
}

#[test]
fn test_linked_vec() -> Result<(), Error> {
    let mut lv: VersionedVec<(u32, String)> = VersionedVec::new();
    assert_eq!(lv.len(), 0);

    lv.insert_new_chain(
        vec![
            (1, "key1".to_string()),
            (11, "key11".to_string()),
            (11, "key111".to_string()),
        ]
        .into_iter(),
    )?;
    lv.insert_new_chain(vec![(2, "key2".to_string()), (22, "key22".to_string())].into_iter())?;
    lv.insert_new_chain(vec![(3, "key3".to_string())].into_iter())?;

    assert_eq!(lv.data.len(), 3);
    assert_eq!(lv.len(), 6);

    assert!(lv.pop_back(0).is_some());
    assert_eq!(lv.len(), 5);

    assert!(lv.pop_back(1).is_some());
    assert_eq!(lv.len(), 4);

    assert!(lv.pop_back(2).is_some());
    assert_eq!(lv.len(), 3);
    // the chain 3 was completely removed
    assert!(lv.pop_back(2).is_none());

    assert_eq!(lv.iter_chain(0).collect::<Vec<_>>().len(), 2);

    Ok(())
}
