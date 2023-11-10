use std::collections::LinkedList;

use crate::Error;

#[derive(Default)]
pub struct LinkedVec<K, V>
where
    K: PartialEq + Eq,
{
    data: Vec<LinkedList<(K, V)>>,
}

impl<K, V> LinkedVec<K, V>
where
    K: PartialEq + Eq,
{
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    pub fn len(&self) -> usize {
        self.data.iter().map(|list| list.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn insert_new_chain(
        &mut self,
        iterator: impl Iterator<Item = (K, V)>,
    ) -> Result<(), Error> {
        let mut new_list = LinkedList::new();
        for (key, value) in iterator {
            new_list.push_front((key, value));
        }

        self.data.push(new_list);

        Ok(())
    }

    pub fn pop_chain(&mut self, chain_index: usize, stop_key: &K) -> Result<(), Error> {
        let list = &mut self.data[chain_index];

        while let Some((key, _)) = list.back() {
            if key == stop_key {
                return Ok(());
            }
            list.pop_back();
        }
        Err(Error::KeyError("Stop key was not found".to_string()))
    }

    pub fn iter_chain(&self, chain_index: usize) -> impl Iterator<Item = &(K, V)> {
        self.data[chain_index].iter()
    }
}

#[test]
fn test_linked_vec() -> Result<(), Error> {
    let mut lv: LinkedVec<u32, String> = LinkedVec::new();
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

    lv.pop_chain(0, &11)?;
    assert_eq!(lv.len(), 5);

    lv.pop_chain(1, &22)?;
    assert_eq!(lv.len(), 4);

    assert!(lv.pop_chain(2, &0).is_err()); // key 0 was never reached
    assert_eq!(lv.len(), 3); // the chain 3 was completely removed

    assert_eq!(lv.iter_chain(0).collect::<Vec<_>>().len(), 2);

    Ok(())
}
