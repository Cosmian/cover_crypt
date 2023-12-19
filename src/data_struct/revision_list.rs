use std::cmp::min;

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

type Link<T> = Option<Box<Element<T>>>;

#[derive(Default, Debug, PartialEq, Eq)]
pub struct RevisionList<T> {
    pub(crate) length: usize,
    pub(crate) head: Link<T>,
}

impl<T> RevisionList<T> {
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

    /*pub fn prepend(&mut self, new_values: impl Iterator<Item = T>) -> &mut Link<T> {
        let previous_head = self.head.take();
        let mut insertion_cursor = &mut self.head;
        for val in new_values {
            let new_element: Element<T> = Element::new(val);
            insertion_cursor = &mut insertion_cursor.insert(Box::new(new_element)).next;
            self.length += 1;
        }
        if let Some(previous_head) = previous_head {
            insertion_cursor.replace(previous_head);
        }
        insertion_cursor
    }*/

    pub fn cursor(&mut self) -> Cursor<'_, T> {
        Cursor::new(self)
    }

    /// Keeps the n first elements of the list and returns the removed ones.
    pub fn keep(&mut self, n: usize) -> RevisionListIter<T> {
        self.length = min(self.length, n);
        if n == 0 {
            return RevisionListIter::new(self.head.take());
        }

        let mut cursor = self.head.as_mut();
        let mut n = n;
        while let Some(next_element) = cursor {
            n -= 1;
            if n == 0 {
                return RevisionListIter::new(next_element.next.take());
            } else {
                cursor = next_element.next.as_mut();
            }
        }
        // n is greater than list size
        RevisionListIter::new(None)
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        RefRevisionListIter::new(self)
    }
}

impl<T> IntoIterator for RevisionList<T> {
    type IntoIter = RevisionListIter<T>;
    type Item = T;

    fn into_iter(self) -> Self::IntoIter {
        RevisionListIter::new(self.head)
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

pub struct Cursor<'a, T> {
    rev_list_len: &'a mut usize,
    cursor_ptr: Option<&'a mut Link<T>>,
    cursor_position: usize,
}

impl<'a, T> Cursor<'a, T> {
    pub fn new(rev_list: &'a mut RevisionList<T>) -> Self {
        Self {
            rev_list_len: &mut rev_list.length,
            cursor_ptr: Some(&mut rev_list.head),
            cursor_position: 0,
        }
    }

    pub fn prepend(&mut self, new_values: impl Iterator<Item = T>) {
        let Some(mut cursor) = self.cursor_ptr.take() else {
            return;
        };
        let previous_element = cursor.take();

        for val in new_values {
            let new_element: Element<T> = Element::new(val);
            cursor = &mut cursor.insert(Box::new(new_element)).next;
            *self.rev_list_len += 1;
            self.cursor_position += 1;
        }
        if let Some(previous_element) = previous_element {
            cursor.replace(previous_element);
        }
        self.cursor_ptr = Some(cursor);
    }

    pub fn skip_while(&mut self, mut f: impl FnMut(&T) -> bool) {
        loop {
            if let Some(Some(element)) = &self.cursor_ptr {
                {
                    if !f(&element.data) {
                        return;
                    }
                }
            } else {
                return;
            }
            let element = self.cursor_ptr.take().unwrap().as_mut().unwrap();
            self.cursor_ptr = Some(&mut element.next);
            self.cursor_position += 1;
        }
    }

    pub fn cutoff(&mut self) {
        if let Some(cursor) = self.cursor_ptr.take() {
            *self.rev_list_len = self.cursor_position;
            cursor.take();
        }
    }
}

pub struct RefRevisionListIter<'a, T> {
    current_element: &'a Link<T>,
}

impl<'a, T> RefRevisionListIter<'a, T> {
    pub fn new(rev_list: &'a RevisionList<T>) -> Self {
        Self {
            current_element: &rev_list.head,
        }
    }
}

impl<'a, T> Iterator for RefRevisionListIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        let element = self.current_element.as_ref()?;
        self.current_element = &element.next;
        Some(&element.data)
    }
}

pub struct RevisionListIter<T> {
    current_element: Link<T>,
}

impl<T> RevisionListIter<T> {
    pub fn new(start_element: Link<T>) -> Self {
        Self {
            current_element: start_element,
        }
    }
}

impl<T> Iterator for RevisionListIter<T> {
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
        let mut revision_list: RevisionList<i32> = RevisionList::new();
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
        let revision_list: RevisionList<i32> = input_iter.collect();

        assert_eq!(revision_list.len(), 3);

        let mut iter = revision_list.iter();
        assert_eq!(iter.next(), Some(&1));
        assert_eq!(iter.next(), Some(&2));
        assert_eq!(iter.next(), Some(&3));
        assert_eq!(iter.next(), None);

        // Test iterator behavior on an empty list
        let revision_list: RevisionList<i32> = RevisionList::new();
        let mut iter = revision_list.iter();
        assert_eq!(iter.next(), None);
        assert!(revision_list.is_empty());
    }

    #[test]
    fn test_revision_list_cursor() {
        let mut revision_list = RevisionList::new();
        revision_list.push_front(1);

        // Add input while value is superior to 1
        let input = [3, 2, 1, 0];
        let mut input_iter = input.iter();
        let mut cursor = revision_list.cursor();

        cursor.prepend(input_iter.by_ref().take_while(|&x| *x > 1).cloned());
        // Consumed the one
        assert_eq!(input_iter.next(), Some(&0));

        cursor.skip_while(|x| *x > 1);
        cursor.cutoff();
        assert_eq!(revision_list.len(), 2);
        let mut iter = revision_list.iter();
        assert_eq!(iter.next(), Some(&3));
        assert_eq!(iter.next(), Some(&2));
        assert_eq!(iter.next(), None);
    }
}
