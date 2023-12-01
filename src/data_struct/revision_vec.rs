use std::{
    collections::{HashSet, VecDeque},
    hash::Hash,
    iter,
};

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
#[derive(Default, Debug, PartialEq, Eq)]
pub struct RevisionVec<K, T> {
    chains: Vec<RevisionList<K, T>>,
    length: usize,
}

impl<K, T> RevisionVec<K, T> {
    pub fn new() -> Self {
        Self {
            chains: Vec::new(),
            length: 0,
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            chains: Vec::with_capacity(capacity),
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
        self.chains.len()
    }

    /// Insert new chain entries in order of arrival
    pub fn insert_new_chain(&mut self, key: K, iter: impl Iterator<Item = T>) {
        let new_chain = RevisionList::from_iter(key, iter);
        if !new_chain.is_empty() {
            self.length += new_chain.len();
            self.chains.push(new_chain);
        }
    }

    pub fn clear(&mut self) {
        self.chains.clear();
        self.length = self.chains.len();
    }

    pub fn retain_keys(&mut self, keys: HashSet<&K>)
    where
        K: Hash + Eq,
    {
        self.chains
            .retain(|chain: &RevisionList<K, T>| keys.contains(&chain.key));
    }

    /// Returns an iterator over each key-chains pair
    pub fn iter(&self) -> impl Iterator<Item = (&K, &RevisionList<K, T>)> {
        self.chains.iter().map(|chain| (&chain.key, chain))
    }

    /// Returns an iterator over each key-chains pair that allow modifying chain
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (K, &mut RevisionList<K, T>)>
    where
        K: Clone,
    {
        self.chains
            .iter_mut()
            .map(|chain| (chain.key.clone(), chain))
    }

    /// Iterates through all versions of all entries
    /// Returns the key and value for each entry.
    pub fn flat_iter(&self) -> impl Iterator<Item = (&K, &T)> {
        self.chains.iter().flat_map(|chain| chain.iter())
    }

    pub fn bfs(&self) -> BfsIterator<T> {
        BfsIterator::new(self)
    }
}

pub struct BfsIterator<'a, T> {
    queue: VecDeque<&'a Element<T>>,
}

impl<'a, T> BfsIterator<'a, T> {
    pub fn new<K>(revision_vec: &'a RevisionVec<K, T>) -> Self {
        // add all chain heads to the iterator queue
        Self {
            queue: revision_vec
                .chains
                .iter()
                .filter_map(|chain| Some(chain.head.as_ref()?.as_ref()))
                .collect(),
        }
    }
}

impl<'a, T> Iterator for BfsIterator<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        // get first element in the iterator queue
        let current_element = self.queue.pop_front()?;
        if let Some(next_element) = current_element.next.as_ref() {
            // add next element of this chain at the back of the queue
            self.queue.push_back(next_element);
        }
        Some(&current_element.data)
    }
}

/// Create `RevisionVec` from an iterator, each element will be inserted in a
/// different chain. Use `insert_new_chain` to collect an iterator inside the
/// same chain.
impl<K, T> FromIterator<(K, T)> for RevisionVec<K, T> {
    fn from_iter<I: IntoIterator<Item = (K, T)>>(iter: I) -> Self {
        let iterator = iter.into_iter();
        let mut vec = Self::with_capacity(iterator.size_hint().0);
        for (key, item) in iterator {
            vec.insert_new_chain(key, iter::once(item))
        }
        vec
    }
}

#[derive(Default, Debug, PartialEq, Eq)]
pub struct Element<T> {
    pub(crate) data: T,
    pub(crate) next: Option<Box<Element<T>>>,
}

impl<T> Element<T> {
    pub fn new(item: T) -> Self {
        Self {
            data: item,
            next: None,
        }
    }
}

#[derive(Default, Debug, PartialEq, Eq)]
pub struct RevisionList<K, T> {
    key: K,
    pub(crate) length: usize,
    pub(crate) head: Option<Box<Element<T>>>,
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

    /// Creates a `RevisionList` from an iterator by inserting elements in the
    /// order of arrival: first item in the iterator will end up at the front.
    pub fn from_iter(key: K, mut iter: impl Iterator<Item = T>) -> Self {
        if let Some(first_element) = iter.next() {
            let mut length = 1;
            let mut head = Some(Box::new(Element::new(first_element)));
            let mut current_element = head.as_mut().expect("next element was inserted above");
            for next_item in iter {
                current_element.next = Some(Box::new(Element::new(next_item)));
                current_element = current_element
                    .next
                    .as_mut()
                    .expect("next element was inserted above");
                length += 1;
            }
            Self { key, length, head }
        } else {
            Self {
                key,
                length: 0,
                head: None,
            }
        }
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

    #[test]
    fn test_revision_vec() {
        todo!()
    }
}
