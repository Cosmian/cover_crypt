use std::collections::VecDeque;

use super::error::Error;

/// a `RevisionVec` stores for each entry a linked list of versions.
/// The entry versions are stored in reverse chronological order:
///
/// Vec [
///     0: key -> a" -> a' -> a
///     1: key -> b
///     2: key -> c' -> c
/// ]
///
/// Insertions are only allowed at the front of the linked list.
/// Deletions can only happen at the end of the linked list.
///
/// This guarantees that the entry versions are always ordered.
// TODO: does index matter for Eq compare?
// TODO: check Serialize/Deserialize
#[derive(Default, Debug, PartialEq, Eq)]
pub struct RevisionVec<K, T> {
    data: Vec<RevisionList<K, T>>,
    length: usize,
}

impl<K, T> RevisionVec<K, T> {
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

    pub fn nb_chains(&self) -> usize {
        self.data.len()
    }

    pub fn chain_length(&self, chain_index: usize) -> usize {
        self.data[chain_index].len()
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
    pub fn insert_new_chain(&mut self, _iterator: impl Iterator<Item = T>) {
        /*let mut new_list = LinkedList::new();
        for item in iterator {
            new_list.push_front(item);
        }
        if !new_list.is_empty() {
            self.length += new_list.len();
            self.data.push(new_list);
        }*/
        todo!()
    }

    /// Removes old entry version.
    pub fn pop_back(&mut self, _chain_index: usize) -> Result<T, Error> {
        /*let chain = self
            .data
            .get_mut(chain_index)
            .ok_or(Error::missing_entry(&chain_index))?;

        let removed_item = chain.pop_back().expect("chains should not be empty");
        self.length -= 1;

        if chain.is_empty() {
            self.data.swap_remove(chain_index);
        }

        Ok(removed_item)*/
        todo!()
    }

    pub fn clear(&mut self) {
        self.data.clear();
        self.length = self.data.len();
    }

    /// Provides reference to the current entry version.
    pub fn front(&self, chain_index: usize) -> Option<&T> {
        self.data.get(chain_index)?.front()
    }

    /// Iterates through all versions of an entry starting from the most recent
    /// one.
    pub fn iter_chain(&self, chain_index: usize) -> impl Iterator<Item = &T> {
        self.data[chain_index].iter().map(|(_, v)| v)
    }

    /// Iterates through all versions of all entries
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.data
            .iter()
            .flat_map(|chain| chain.iter().map(|(_, v)| v))
    }

    pub fn bfs(&self) -> BfsIterator<T> {
        BfsIterator::new(self)
    }
}

pub struct BfsIterator<'a, T> {
    chains: VecDeque<&'a Element<T>>,
}

impl<'a, T> BfsIterator<'a, T> {
    pub fn new<K>(_versioned_vec: &'a RevisionVec<K, T>) -> Self {
        todo!()
    }
}

impl<'a, T> Iterator for BfsIterator<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        /*loop {
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
        }*/
        todo!()
    }
}

/// Create VersionedVec from an iterator, each element will be inserted in a
/// different chain. Use `insert_new_chain` to collect an iterator inside the
/// same chain.
impl<K, T> FromIterator<T> for RevisionVec<K, T> {
    fn from_iter<I: IntoIterator<Item = T>>(_iter: I) -> Self {
        /*let iterator = iter.into_iter();
        let mut vec = Self::with_capacity(iterator.size_hint().0);
        for item in iterator {
            vec.insert_new_chain(iter::once(item))
        }
        vec*/
        todo!()
    }
}

#[derive(Default, Debug, PartialEq, Eq)]
struct Element<T> {
    data: T,
    next: Option<Box<Element<T>>>,
}

#[derive(Default, Debug, PartialEq, Eq)]
pub struct RevisionList<K, T> {
    key: K,
    length: usize,
    head: Option<Box<Element<T>>>,
}

impl<K, T> RevisionList<K, T> {
    pub fn new(key: K) -> Self {
        Self {
            key,
            length: 0,
            head: None,
        }
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    pub fn push_front(&mut self, val: T) {
        let new_element = Element {
            data: val,
            next: self.head.take(),
        };

        self.head = Some(Box::new(new_element));
        self.length += 1;
    }

    pub fn front(&self) -> Option<&T> {
        self.head.as_ref().map(|element| &element.data)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &T)> {
        RevisionListIter::new(self)
    }
}

pub struct RevisionListIter<'a, K, T> {
    key: &'a K,
    current_element: &'a Option<Box<Element<T>>>,
}

impl<'a, K, T> RevisionListIter<'a, K, T> {
    pub fn new(rev_list: &'a RevisionList<K, T>) -> Self {
        Self {
            key: &rev_list.key,
            current_element: &rev_list.head,
        }
    }
}

impl<'a, K, T> Iterator for RevisionListIter<'a, K, T> {
    type Item = (&'a K, &'a T);

    fn next(&mut self) -> Option<Self::Item> {
        let element = self.current_element.as_ref()?;
        self.current_element = &element.next;
        Some((self.key, &element.data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_revision_vec() -> Result<(), Error> {
        todo!()
    }
}
