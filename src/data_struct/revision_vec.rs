use std::{
    collections::{HashSet, VecDeque},
    hash::Hash,
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
    chains: Vec<(K, RevisionList<T>)>,
}

impl<K, T> RevisionVec<K, T> {
    pub fn new() -> Self {
        Self { chains: Vec::new() }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            chains: Vec::with_capacity(capacity),
        }
    }

    pub fn len(&self) -> usize {
        self.chains.iter().map(|(_, chain)| chain.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn nb_chains(&self) -> usize {
        self.chains.len()
    }

    /// Creates and insert a new chain with a single value.
    /// /!\ Adding multiple chains with the same key will corrupt the data
    /// structure.
    pub fn create_chain_with_single_value(&mut self, key: K, val: T) {
        let mut new_chain = RevisionList::new();
        new_chain.push_front(val);
        self.chains.push((key, new_chain));
    }

    /// Inserts a new chain with a corresponding key.
    /// /!\ Adding multiple chains with the same key will corrupt the data
    /// structure.
    pub fn insert_new_chain(&mut self, key: K, new_chain: RevisionList<T>) {
        if !new_chain.is_empty() {
            self.chains.push((key, new_chain));
        }
    }

    pub fn clear(&mut self) {
        self.chains.clear();
    }

    pub fn retain_keys(&mut self, keys: HashSet<&K>)
    where
        K: Hash + Eq,
    {
        self.chains.retain(|(key, _)| keys.contains(key));
    }

    /// Returns an iterator over each key-chains pair
    pub fn iter(&self) -> impl Iterator<Item = (&K, &RevisionList<T>)> {
        self.chains.iter().map(|(key, chain)| (key, chain))
    }

    /// Returns an iterator over each key-chains pair that allow modifying chain
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&K, &mut RevisionList<T>)>
    where
        K: Clone,
    {
        self.chains.iter_mut().map(|(ref key, chain)| (key, chain))
    }

    /// Iterates through all versions of all entries
    /// Returns the key and value for each entry.
    pub fn flat_iter(&self) -> impl Iterator<Item = (&K, &T)> {
        self.chains
            .iter()
            .flat_map(|(key, chain)| chain.iter().map(move |val| (key, val)))
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
                .filter_map(|(_, chain)| Some(chain.head.as_ref()?.as_ref()))
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
pub struct RevisionList<T> {
    pub(crate) length: usize,
    pub(crate) head: Option<Box<Element<T>>>,
}

impl<T> RevisionList<T> {
    pub fn new() -> Self {
        Self {
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

    pub fn pop_tail(&mut self) -> RevisionListIter<T> {
        self.length = self.head.as_ref().map_or(0, |_| 1);
        match &self.head {
            Some(head) => RevisionListIter {
                current_element: &head.next,
            },
            None => RevisionListIter {
                current_element: &None,
            },
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        RevisionListIter::new(self)
    }
}

impl<T> FromIterator<T> for RevisionList<T> {
    /// Creates a `RevisionList` from an iterator by inserting elements in the
    /// order of arrival: first item in the iterator will end up at the front.
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut iterator = iter.into_iter();
        if let Some(first_element) = iterator.next() {
            let mut length = 1;
            let mut head = Some(Box::new(Element::new(first_element)));
            let mut current_element = head.as_mut().expect("element was inserted above");
            for next_item in iterator {
                current_element.next = Some(Box::new(Element::new(next_item)));
                current_element = current_element
                    .next
                    .as_mut()
                    .expect("element was inserted above");
                length += 1;
            }
            Self { length, head }
        } else {
            Self {
                length: 0,
                head: None,
            }
        }
    }
}

pub struct RevisionListIter<'a, T> {
    current_element: &'a Option<Box<Element<T>>>,
}

impl<'a, T> RevisionListIter<'a, T> {
    pub fn new(rev_list: &'a RevisionList<T>) -> Self {
        Self {
            current_element: &rev_list.head,
        }
    }
}

impl<'a, T> Iterator for RevisionListIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        let element = self.current_element.as_ref()?;
        self.current_element = &element.next;
        Some(&element.data)
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_revision_vec() {
        todo!()
    }
}
