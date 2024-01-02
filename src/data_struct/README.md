# Data structures to store Covercrypt objects

## Overview

### Dictionary

A `Dictionary` is a `HashMap` keeping insertion order inspired by Python dictionary.
It is used to store ordered `Dimension` (also named axis) inside the `Policy` object.

Pros:

- the hierarchical order of the attributes is kept by design

- same serialized size

- accessing elements is the almost as fast as an `HashMap` with one additional memory access

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

- following linked list pointers can be slower than iterating a regular vector

- serialization requires following each linked list

### RevisionList

A `RevisionList` is a linked list with only next pointers.

It provided a `Cursor` interface to access and modify the elements while following the next pointers.
This type of interface is not available in stable Rust `LinkedList`.

It is used by both the `RevisionMap` and `RevisionVec`.

## Benchmark

```text
Edit Policy/edit policy time:   [346.46 µs 346.72 µs 346.98 µs]
                        change: [-25.395% -25.260% -25.136%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 1552 outliers among 5000 measurements (31.04%)
  675 (13.50%) low mild
  317 (6.34%) high mild
  560 (11.20%) high severe

Header encryption/1 partition(s), 1 access
                        time:   [98.350 µs 98.387 µs 98.425 µs]
                        change: [-0.7784% -0.5652% -0.3640%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 215 outliers among 5000 measurements (4.30%)
  138 (2.76%) low mild
  63 (1.26%) high mild
  14 (0.28%) high severe
Header encryption/2 partition(s), 1 access
                        time:   [151.39 µs 151.45 µs 151.51 µs]
                        change: [-0.5608% -0.4164% -0.2837%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 368 outliers among 5000 measurements (7.36%)
  251 (5.02%) low mild
  95 (1.90%) high mild
  22 (0.44%) high severe
Header encryption/3 partition(s), 1 access
                        time:   [201.25 µs 201.37 µs 201.50 µs]
                        change: [-2.2096% -2.0478% -1.8971%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 179 outliers among 5000 measurements (3.58%)
  2 (0.04%) low mild
  144 (2.88%) high mild
  33 (0.66%) high severe
Header encryption/4 partition(s), 1 access
                        time:   [253.42 µs 253.56 µs 253.71 µs]
                        change: [-2.6348% -2.4339% -2.2435%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 127 outliers among 5000 measurements (2.54%)
  109 (2.18%) high mild
  18 (0.36%) high severe
Header encryption/5 partition(s), 1 access
                        time:   [310.58 µs 310.68 µs 310.79 µs]
                        change: [-10.531% -10.397% -10.275%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 256 outliers among 5000 measurements (5.12%)
  85 (1.70%) low mild
  152 (3.04%) high mild
  19 (0.38%) high severe

Benchmarking Header encryption and decryption/ciphertexts with 1 partition(s), usk with 1 partitions: Collecting 5000 samples in estimated 5.2264
Header encryption and decryption/ciphertexts with 1 partition(s), usk with 1 partitions
                        time:   [174.62 µs 174.69 µs 174.76 µs]
                        change: [+0.7357% +0.7906% +0.8508%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 84 outliers among 5000 measurements (1.68%)
  2 (0.04%) low mild
  61 (1.22%) high mild
  21 (0.42%) high severe
Benchmarking Header encryption and decryption/ciphertexts with 2 partition(s), usk with 1 partitions: Collecting 5000 samples in estimated 6.1381
Header encryption and decryption/ciphertexts with 2 partition(s), usk with 1 partitions
                        time:   [243.74 µs 243.95 µs 244.16 µs]
                        change: [+0.6880% +0.8225% +0.9473%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 39 outliers among 5000 measurements (0.78%)
  18 (0.36%) low mild
  20 (0.40%) high mild
  1 (0.02%) high severe
Benchmarking Header encryption and decryption/ciphertexts with 3 partition(s), usk with 1 partitions: Collecting 5000 samples in estimated 6.2358
Header encryption and decryption/ciphertexts with 3 partition(s), usk with 1 partitions
                        time:   [312.47 µs 312.84 µs 313.21 µs]
                        change: [+0.7563% +0.9329% +1.1015%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 12 outliers among 5000 measurements (0.24%)
  3 (0.06%) low mild
  9 (0.18%) high mild
Benchmarking Header encryption and decryption/ciphertexts with 4 partition(s), usk with 1 partitions: Collecting 5000 samples in estimated 5.6795
Header encryption and decryption/ciphertexts with 4 partition(s), usk with 1 partitions
                        time:   [379.10 µs 379.67 µs 380.25 µs]
                        change: [+0.1993% +0.4121% +0.6339%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 1 outliers among 5000 measurements (0.02%)
  1 (0.02%) high mild
Benchmarking Header encryption and decryption/ciphertexts with 5 partition(s), usk with 1 partitions: Collecting 5000 samples in estimated 6.6435
Header encryption and decryption/ciphertexts with 5 partition(s), usk with 1 partitions
                        time:   [442.68 µs 443.41 µs 444.15 µs]
                        change: [-2.1034% -1.8470% -1.5882%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 8 outliers among 5000 measurements (0.16%)
  1 (0.02%) low mild
  7 (0.14%) high mild
Benchmarking Header encryption and decryption/ciphertexts with 1 partition(s), usk with 2 partitions: Collecting 5000 samples in estimated 5.2588
Header encryption and decryption/ciphertexts with 1 partition(s), usk with 2 partitions
                        time:   [175.06 µs 175.12 µs 175.19 µs]
                        change: [-14.201% -14.151% -14.103%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 442 outliers among 5000 measurements (8.84%)
  364 (7.28%) low mild
  64 (1.28%) high mild
  14 (0.28%) high severe
Benchmarking Header encryption and decryption/ciphertexts with 2 partition(s), usk with 2 partitions: Collecting 5000 samples in estimated 5.1292
Header encryption and decryption/ciphertexts with 2 partition(s), usk with 2 partitions
                        time:   [255.61 µs 256.05 µs 256.49 µs]
                        change: [-11.225% -11.024% -10.826%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 3 outliers among 5000 measurements (0.06%)
  3 (0.06%) high mild
Benchmarking Header encryption and decryption/ciphertexts with 3 partition(s), usk with 2 partitions: Collecting 5000 samples in estimated 5.0856
Header encryption and decryption/ciphertexts with 3 partition(s), usk with 2 partitions
                        time:   [338.08 µs 338.92 µs 339.76 µs]
                        change: [-9.3124% -9.0137% -8.7142%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 6 outliers among 5000 measurements (0.12%)
  5 (0.10%) high mild
  1 (0.02%) high severe
Benchmarking Header encryption and decryption/ciphertexts with 4 partition(s), usk with 2 partitions: Collecting 5000 samples in estimated 6.3907
Header encryption and decryption/ciphertexts with 4 partition(s), usk with 2 partitions
                        time:   [425.62 µs 426.74 µs 427.87 µs]
                        change: [-6.6440% -6.3037% -5.9372%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 1 outliers among 5000 measurements (0.02%)
  1 (0.02%) high mild
Benchmarking Header encryption and decryption/ciphertexts with 5 partition(s), usk with 2 partitions: Collecting 5000 samples in estimated 5.0413
Header encryption and decryption/ciphertexts with 5 partition(s), usk with 2 partitions
                        time:   [501.61 µs 503.34 µs 505.08 µs]
                        change: [-6.5008% -6.0734% -5.6270%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 4 outliers among 5000 measurements (0.08%)
  4 (0.08%) high mild
Benchmarking Header encryption and decryption/ciphertexts with 1 partition(s), usk with 3 partitions: Collecting 5000 samples in estimated 5.2359
Header encryption and decryption/ciphertexts with 1 partition(s), usk with 3 partitions
                        time:   [190.48 µs 190.90 µs 191.33 µs]
                        change: [-6.8449% -6.6297% -6.4037%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 3 outliers among 5000 measurements (0.06%)
  3 (0.06%) high severe
Benchmarking Header encryption and decryption/ciphertexts with 2 partition(s), usk with 3 partitions: Collecting 5000 samples in estimated 5.4179
Header encryption and decryption/ciphertexts with 2 partition(s), usk with 3 partitions
                        time:   [270.74 µs 271.38 µs 272.02 µs]
                        change: [-11.729% -11.406% -11.088%] (p = 0.00 < 0.05)
                        Performance has improved.
Benchmarking Header encryption and decryption/ciphertexts with 3 partition(s), usk with 3 partitions: Collecting 5000 samples in estimated 5.5672
Header encryption and decryption/ciphertexts with 3 partition(s), usk with 3 partitions
                        time:   [369.57 µs 370.79 µs 372.02 µs]
                        change: [-8.4226% -8.0060% -7.5889%] (p = 0.00 < 0.05)
                        Performance has improved.
Benchmarking Header encryption and decryption/ciphertexts with 4 partition(s), usk with 3 partitions: Collecting 5000 samples in estimated 7.0293
Header encryption and decryption/ciphertexts with 4 partition(s), usk with 3 partitions
                        time:   [466.25 µs 467.95 µs 469.65 µs]
                        change: [-6.9419% -6.4231% -5.9092%] (p = 0.00 < 0.05)
                        Performance has improved.
Benchmarking Header encryption and decryption/ciphertexts with 5 partition(s), usk with 3 partitions: Collecting 5000 samples in estimated 5.7422
Header encryption and decryption/ciphertexts with 5 partition(s), usk with 3 partitions
                        time:   [572.05 µs 574.71 µs 577.37 µs]
                        change: [-4.8369% -4.2561% -3.6419%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 5 outliers among 5000 measurements (0.10%)
  5 (0.10%) high mild
Benchmarking Header encryption and decryption/ciphertexts with 1 partition(s), usk with 4 partitions: Collecting 5000 samples in estimated 5.7158
Header encryption and decryption/ciphertexts with 1 partition(s), usk with 4 partitions
                        time:   [203.77 µs 203.91 µs 204.05 µs]
                        change: [+17.477% +17.567% +17.665%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 193 outliers among 5000 measurements (3.86%)
  4 (0.08%) low severe
  18 (0.36%) low mild
  99 (1.98%) high mild
  72 (1.44%) high severe
Benchmarking Header encryption and decryption/ciphertexts with 2 partition(s), usk with 4 partitions: Collecting 5000 samples in estimated 5.7854
Header encryption and decryption/ciphertexts with 2 partition(s), usk with 4 partitions
                        time:   [290.66 µs 291.63 µs 292.61 µs]
                        change: [+1.1010% +1.5470% +2.0449%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 32 outliers among 5000 measurements (0.64%)
  22 (0.44%) high mild
  10 (0.20%) high severe
Benchmarking Header encryption and decryption/ciphertexts with 3 partition(s), usk with 4 partitions: Collecting 5000 samples in estimated 6.0392
Header encryption and decryption/ciphertexts with 3 partition(s), usk with 4 partitions
                        time:   [398.65 µs 400.31 µs 401.94 µs]
                        change: [-1.0342% -0.4658% +0.0952%] (p = 0.11 > 0.05)
                        No change in performance detected.
Benchmarking Header encryption and decryption/ciphertexts with 4 partition(s), usk with 4 partitions: Collecting 5000 samples in estimated 5.1925
Header encryption and decryption/ciphertexts with 4 partition(s), usk with 4 partitions
                        time:   [518.30 µs 521.03 µs 523.79 µs]
                        change: [-13.757% -13.117% -12.467%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 3 outliers among 5000 measurements (0.06%)
  2 (0.04%) high mild
  1 (0.02%) high severe
Benchmarking Header encryption and decryption/ciphertexts with 5 partition(s), usk with 4 partitions: Collecting 5000 samples in estimated 7.2000
Header encryption and decryption/ciphertexts with 5 partition(s), usk with 4 partitions
                        time:   [716.16 µs 720.16 µs 724.19 µs]
                        change: [+12.240% +13.155% +14.062%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 1 outliers among 5000 measurements (0.02%)
  1 (0.02%) high mild
Benchmarking Header encryption and decryption/ciphertexts with 1 partition(s), usk with 5 partitions: Collecting 5000 samples in estimated 5.9475
Header encryption and decryption/ciphertexts with 1 partition(s), usk with 5 partitions
                        time:   [237.56 µs 237.90 µs 238.26 µs]
                        change: [-11.788% -11.613% -11.448%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 82 outliers among 5000 measurements (1.64%)
  1 (0.02%) low mild
  28 (0.56%) high mild
  53 (1.06%) high severe
Benchmarking Header encryption and decryption/ciphertexts with 2 partition(s), usk with 5 partitions: Collecting 5000 samples in estimated 5.4984
Header encryption and decryption/ciphertexts with 2 partition(s), usk with 5 partitions
                        time:   [365.00 µs 366.27 µs 367.53 µs]
                        change: [-8.4883% -8.0219% -7.5736%] (p = 0.00 < 0.05)
                        Performance has improved.
Benchmarking Header encryption and decryption/ciphertexts with 3 partition(s), usk with 5 partitions: Collecting 5000 samples in estimated 7.3921
Header encryption and decryption/ciphertexts with 3 partition(s), usk with 5 partitions
                        time:   [491.27 µs 493.30 µs 495.33 µs]
                        change: [-8.4819% -7.8614% -7.2815%] (p = 0.00 < 0.05)
                        Performance has improved.
Benchmarking Header encryption and decryption/ciphertexts with 4 partition(s), usk with 5 partitions: Collecting 5000 samples in estimated 6.2096
Header encryption and decryption/ciphertexts with 4 partition(s), usk with 5 partitions
                        time:   [620.44 µs 623.86 µs 627.30 µs]
                        change: [-5.9588% -5.2564% -4.5034%] (p = 0.00 < 0.05)
                        Performance has improved.
Benchmarking Header encryption and decryption/ciphertexts with 5 partition(s), usk with 5 partitions: Collecting 5000 samples in estimated 7.5536
Header encryption and decryption/ciphertexts with 5 partition(s), usk with 5 partitions
                        time:   [758.17 µs 762.63 µs 767.09 µs]
                        change: [-4.4494% -3.6664% -2.8574%] (p = 0.00 < 0.05)
                        Performance has improved.

bench header encryption size:
1 partition(s): 1171 bytes
2 partition(s): 2260 bytes
3 partition(s): 3349 bytes
4 partition(s): 4438 bytes
5 partition(s): 5527 bytes
1 usk partition(s): 1286 bytes
2 usk partition(s): 2475 bytes
3 usk partition(s): 3664 bytes
4 usk partition(s): 4853 bytes
5 usk partition(s): 6042 bytes
Key serialization/MSK   time:   [4.4242 µs 4.4278 µs 4.4314 µs]
                        change: [+2.3014% +2.4893% +2.6703%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 83 outliers among 5000 measurements (1.66%)
  50 (1.00%) high mild
  33 (0.66%) high severe
Key serialization/MPK   time:   [58.964 µs 59.056 µs 59.154 µs]
                        change: [+0.5632% +0.7261% +0.8992%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 156 outliers among 5000 measurements (3.12%)
  12 (0.24%) low mild
  91 (1.82%) high mild
  53 (1.06%) high severe
Key serialization/USK 1 partition
                        time:   [372.12 ns 372.27 ns 372.43 ns]
                        change: [+4.6778% +4.7747% +4.8727%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 243 outliers among 5000 measurements (4.86%)
  20 (0.40%) low severe
  60 (1.20%) low mild
  86 (1.72%) high mild
  77 (1.54%) high severe

Header serialization/1 partition(s)
                        time:   [6.6707 µs 6.6743 µs 6.6780 µs]
                        change: [-0.4660% -0.3933% -0.3223%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 132 outliers among 5000 measurements (2.64%)
  21 (0.42%) low mild
  96 (1.92%) high mild
  15 (0.30%) high severe
Header serialization/2 partition(s)
                        time:   [6.9437 µs 6.9474 µs 6.9511 µs]
                        change: [-0.3677% -0.2924% -0.2154%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 107 outliers among 5000 measurements (2.14%)
  8 (0.16%) low mild
  88 (1.76%) high mild
  11 (0.22%) high severe
Header serialization/3 partition(s)
                        time:   [7.2540 µs 7.2573 µs 7.2606 µs]
                        change: [-0.2912% -0.0941% +0.0812%] (p = 0.33 > 0.05)
                        No change in performance detected.
Found 87 outliers among 5000 measurements (1.74%)
  1 (0.02%) low severe
  7 (0.14%) low mild
  59 (1.18%) high mild
  20 (0.40%) high severe
Header serialization/4 partition(s)
                        time:   [7.4640 µs 7.4678 µs 7.4715 µs]
                        change: [-1.0412% -0.8816% -0.7317%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 104 outliers among 5000 measurements (2.08%)
  20 (0.40%) low mild
  81 (1.62%) high mild
  3 (0.06%) high severe
Header serialization/5 partition(s)
                        time:   [7.8154 µs 7.8322 µs 7.8510 µs]
                        change: [+0.9561% +1.1993% +1.4289%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 85 outliers among 5000 measurements (1.70%)
  35 (0.70%) high mild
  50 (1.00%) high severe
```
