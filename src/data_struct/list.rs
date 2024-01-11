type Link<T> = Option<Box<Element<T>>>;

#[derive(Default, Debug, PartialEq, Eq)]
pub struct Element<T> {
    pub(crate) data: T,
    pub(crate) next: Link<T>,
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
pub struct List<T> {
    pub(crate) length: usize,
    pub(crate) head: Link<T>,
}

impl<T> List<T> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            length: 0,
            head: None,
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.length
    }

    #[must_use]
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

    #[must_use]
    pub fn front(&self) -> Option<&T> {
        self.head.as_ref().map(|element| &element.data)
    }

    pub fn front_mut(&mut self) -> Option<&mut T> {
        self.head.as_mut().map(|element| &mut element.data)
    }

    /// Keeps the n first elements of the list and returns the removed ones.
    pub fn keep(&mut self, n: usize) -> ListIter<T> {
        let mut current_element = &mut self.head;
        for _ in 0..n {
            if let Some(element) = current_element {
                current_element = &mut element.next;
            } else {
                return ListIter::new(None);
            }
        }
        self.length = n;
        ListIter::new(current_element.take())
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        RefListIter::new(self)
    }
}

impl<T> IntoIterator for List<T> {
    type IntoIter = ListIter<T>;
    type Item = T;

    fn into_iter(self) -> Self::IntoIter {
        ListIter::new(self.head)
    }
}

impl<T> FromIterator<T> for List<T> {
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

/// Hacky structure allowing to iterate on and mutate a linked list.
pub struct Cursor<'a, T> {
    list_length: &'a mut usize,
    link: &'a mut Link<T>,
    position: usize,
}

impl<'a, T> Cursor<'a, T> {
    pub fn new(rev_list: &'a mut List<T>) -> Self {
        Self {
            list_length: &mut rev_list.length,
            link: &mut rev_list.head,
            position: 0,
        }
    }

    /// Moves the cursor to the next element in the list.
    pub fn next(mut self) -> Self {
        if let Some(element) = self.link {
            self.link = &mut element.next;
            self.position += 1;
        }
        self
    }

    /// Adds a new value in the list before the current cursor.
    pub fn prepend(self, data: T) -> Self {
        let new_element = Element {
            data,
            next: self.link.take(),
        };
        *self.link = Some(Box::new(new_element));
        *self.list_length += 1;
        self.next()
    }

    /// Moves the cursor down the list while the given predicate is true.
    pub fn skip_while(mut self, mut f: impl FnMut(&T) -> bool) -> Self {
        while self.link.as_ref().map(|e| f(&e.data)) == Some(true) {
            self = self.next();
        }
        self
    }

    /// Removes all elements from the cursor (included) to the end.
    pub fn cutoff(&mut self) {
        self.link.take();
        *self.list_length = self.position;
    }
}

pub struct RefListIter<'a, T> {
    current_element: &'a Link<T>,
}

impl<'a, T> RefListIter<'a, T> {
    pub fn new(rev_list: &'a List<T>) -> Self {
        Self {
            current_element: &rev_list.head,
        }
    }
}

impl<'a, T> Iterator for RefListIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        let element = self.current_element.as_ref()?;
        self.current_element = &element.next;
        Some(&element.data)
    }
}

pub struct ListIter<T> {
    current_element: Link<T>,
}

impl<T> ListIter<T> {
    pub fn new(start_element: Link<T>) -> Self {
        Self {
            current_element: start_element,
        }
    }
}

impl<T> Iterator for ListIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        let element = self.current_element.take()?;
        self.current_element = element.next;
        Some(element.data)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_revision_list() {
        let mut revision_list: List<i32> = List::new();
        assert!(revision_list.is_empty());
        assert_eq!(revision_list.front(), None);

        // Insertions
        revision_list.push_front(1);
        revision_list.push_front(2);
        revision_list.push_front(3);
        assert_eq!(revision_list.len(), 3);

        // Get and iter
        assert_eq!(revision_list.front(), Some(&3));
        {
            let mut iter = revision_list.iter();
            assert_eq!(iter.next(), Some(&3));
            assert_eq!(iter.next(), Some(&2));
            assert_eq!(iter.next(), Some(&1));
            assert_eq!(iter.next(), None);
        }

        // Keep and remove elements
        let popped_tail = revision_list.keep(1).collect::<Vec<_>>();
        assert_eq!(popped_tail, vec![2, 1]);
        assert_eq!(revision_list.len(), 1);

        assert_eq!(revision_list.front(), Some(&3));

        revision_list.keep(0);
        assert!(revision_list.is_empty());
    }

    #[test]
    fn test_revision_list_from_iterator() {
        // Test creating RevisionList from iterator
        let input_iter = vec![1, 2, 3].into_iter();
        let revision_list: List<i32> = input_iter.collect();

        assert_eq!(revision_list.len(), 3);

        let mut iter = revision_list.iter();
        assert_eq!(iter.next(), Some(&1));
        assert_eq!(iter.next(), Some(&2));
        assert_eq!(iter.next(), Some(&3));
        assert_eq!(iter.next(), None);

        // Test iterator behavior on an empty list
        let revision_list: List<i32> = List::new();
        let mut iter = revision_list.iter();
        assert_eq!(iter.next(), None);
        assert!(revision_list.is_empty());
    }

    #[test]
    fn test_revision_list_cursor() {
        let mut revision_list = List::new();
        revision_list.push_front(1);

        // Add input while value is superior to 1
        let input = [3, 2, 1, 0];
        let mut input_iter = input.iter().peekable();
        let mut cursor = Cursor::new(&mut revision_list);

        // will add 3 and 2 before the current head
        while let Some(new_value) = input_iter.next_if(|&x| *x > 1) {
            cursor = cursor.prepend(*new_value);
        }

        // consumed the input iterator unit value 1
        assert_eq!(input_iter.next(), Some(&1));

        assert_eq!(revision_list.len(), 3);
        {
            let mut iter = revision_list.iter();
            assert_eq!(iter.next(), Some(&3));
            assert_eq!(iter.next(), Some(&2));
            assert_eq!(iter.next(), Some(&1));
            assert_eq!(iter.next(), None);
        }

        // will remove 2 and 1 from list
        cursor = Cursor::new(&mut revision_list);
        cursor = cursor.skip_while(|x| *x > 2);
        cursor.cutoff();
        assert_eq!(revision_list.len(), 1);
        {
            let mut iter = revision_list.iter();
            assert_eq!(iter.next(), Some(&3));
        }

        // remove the last element
        cursor = Cursor::new(&mut revision_list);
        cursor.cutoff();
        assert!(revision_list.is_empty());
    }
}
