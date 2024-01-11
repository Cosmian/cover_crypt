# Data structures to store Covercrypt objects

## Overview

### Dictionary

A `Dictionary` is a `HashMap` keeping insertion order inspired by Python dictionary.
It is used to store ordered `Dimension` (also named axis) inside the `Policy` object.

Pros:

- the hierarchical order of the attributes is kept by design

- same serialized size

- accessing elements is almost as fast as an `HashMap` with one additional memory access

- updating the key of an element (e.g. renaming an attribute) can be performed in constant time without modifying the order

Cons:

- more space in memory

- removing an element is `O(n)` but ordered dimensions do not allow this modification

### RevisionMap

A `RevisionMap` is a `HashMap` which keys are mapped to sequences of values.
Upon insertion for an existing key, the new value is prepended to the sequence of older values instead of replacing it.

It is used to store master secret key where each coordinate is mapped to a list of keys.
When a coordinate is rekeyed, a new key is generated and added to the front of the associated list inside the `RevisionMap`.

Note: the master public key is a regular `HashMap` only storing the most recent key for any coordinate as one only wants to encrypt new data with the newest key.

Pros:

- constant time access to the most recent key for each coordinate

- adding a new key to the front (rekeying) is performed in constant time

- key history for any coordinate is preserved by design (useful to refresh user keys)

Cons:

- following linked list pointers can be slower than iterating a regular vector

- serialization requires following each linked list

### RevisionVec

A `RevisionVec` is a vector that stores pairs containing a key and a sequence of values.

Inserting a new value in the sequence associated to an existing key prepends this value to the sequence.

It is used to store user secret key where each coordinate is stored with a list of keys.
When refreshing the user key with a given master secret key, each coordinate is updated by comparing the list of user subkeys with the master ones.

Pros:

- accessing the most recent keys is faster than older ones

- updating the user key with a given master secret key is performed by only iterating each linked list once

- key history for any coordinate is preserved by design (useful to refresh user keys)

Cons:

- no direct access to a given coordinate's keys (would be a nice to have but not really needed in practice)

- multiple insertions with the same coordinate will result in multiple entries in the vector thus corrupting the structure

- following linked list pointers can be slower than iterating a regular vector

- serialization requires following each linked list

### List

A `List` is a linked list with only next pointers.

It provided a `Cursor` interface to access and modify the elements while following the next pointers.
This type of interface is not available in stable Rust `LinkedList`.

It is used by both the `RevisionMap` and `RevisionVec`.

## Operations

### Master Secret Key

### User Secret Key
