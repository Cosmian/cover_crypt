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
Edit Policy/edit policy time:   [363.08 µs 363.41 µs 363.75 µs]
                        change: [-15.765% -15.580% -15.405%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 123 outliers among 5000 measurements (2.46%)
  104 (2.08%) high mild
  19 (0.38%) high severe

Header encryption/1 partition(s), 1 access
                        time:   [107.12 µs 107.40 µs 107.69 µs]
                        change: [+5.5096% +5.8408% +6.1846%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 43 outliers among 5000 measurements (0.86%)
  32 (0.64%) high mild
  11 (0.22%) high severe
Header encryption/2 partition(s), 1 access
                        time:   [150.34 µs 150.48 µs 150.63 µs]
                        change: [-0.9637% -0.8428% -0.7319%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 298 outliers among 5000 measurements (5.96%)
  2 (0.04%) low mild
  232 (4.64%) high mild
  64 (1.28%) high severe
Header encryption/3 partition(s), 1 access
                        time:   [208.59 µs 208.73 µs 208.86 µs]
                        change: [-0.0872% +0.1122% +0.2949%] (p = 0.26 > 0.05)
                        No change in performance detected.
Found 215 outliers among 5000 measurements (4.30%)
  8 (0.16%) low mild
  159 (3.18%) high mild
  48 (0.96%) high severe
Header encryption/4 partition(s), 1 access
                        time:   [257.65 µs 257.93 µs 258.23 µs]
                        change: [-0.8967% -0.7898% -0.6665%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 317 outliers among 5000 measurements (6.34%)
  4 (0.08%) low mild
  203 (4.06%) high mild
  110 (2.20%) high severe
Header encryption/5 partition(s), 1 access
                        time:   [312.73 µs 313.12 µs 313.52 µs]
                        change: [-0.5918% -0.4702% -0.3363%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 407 outliers among 5000 measurements (8.14%)
  5 (0.10%) low mild
  236 (4.72%) high mild
  166 (3.32%) high severe

Header encryption and decryption/ciphertexts with 1 partition(s), usk with 1 partitions
                        time:   [186.62 µs 186.93 µs 187.24 µs]
                        change: [+3.6548% +3.8252% +3.9759%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 450 outliers among 5000 measurements (9.00%)
  6 (0.12%) low mild
  337 (6.74%) high mild
  107 (2.14%) high severe
Header encryption and decryption/ciphertexts with 2 partition(s), usk with 1 partitions
                        time:   [249.41 µs 249.69 µs 249.97 µs]
                        change: [-0.6376% -0.4952% -0.3456%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 56 outliers among 5000 measurements (1.12%)
  2 (0.04%) low mild
  40 (0.80%) high mild
  14 (0.28%) high severe
Header encryption and decryption/ciphertexts with 3 partition(s), usk with 1 partitions
                        time:   [321.52 µs 322.05 µs 322.59 µs]
                        change: [-1.4803% -1.2448% -1.0353%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 104 outliers among 5000 measurements (2.08%)
  13 (0.26%) low mild
  42 (0.84%) high mild
  49 (0.98%) high severe
Header encryption and decryption/ciphertexts with 4 partition(s), usk with 1 partitions
                        time:   [420.55 µs 421.77 µs 423.00 µs]
                        change: [+3.4361% +3.8397% +4.2440%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 47 outliers among 5000 measurements (0.94%)
  26 (0.52%) high mild
  21 (0.42%) high severe
Header encryption and decryption/ciphertexts with 5 partition(s), usk with 1 partitions
                        time:   [455.77 µs 456.60 µs 457.43 µs]
                        change: [-1.4805% -1.2550% -1.0145%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 43 outliers among 5000 measurements (0.86%)
  2 (0.04%) low mild
  32 (0.64%) high mild
  9 (0.18%) high severe
Header encryption and decryption/ciphertexts with 1 partition(s), usk with 2 partitions
                        time:   [177.51 µs 177.72 µs 177.93 µs]
                        change: [-1.5408% -1.4154% -1.3025%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 381 outliers among 5000 measurements (7.62%)
  2 (0.04%) low mild
  241 (4.82%) high mild
  138 (2.76%) high severe
Header encryption and decryption/ciphertexts with 2 partition(s), usk with 2 partitions
                        time:   [304.05 µs 304.71 µs 305.38 µs]
                        change: [+12.042% +12.421% +12.825%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 65 outliers among 5000 measurements (1.30%)
  2 (0.04%) low mild
  38 (0.76%) high mild
  25 (0.50%) high severe
Header encryption and decryption/ciphertexts with 3 partition(s), usk with 2 partitions
                        time:   [404.56 µs 405.63 µs 406.69 µs]
                        change: [+15.022% +15.485% +15.911%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 23 outliers among 5000 measurements (0.46%)
  14 (0.28%) high mild
  9 (0.18%) high severe
Header encryption and decryption/ciphertexts with 4 partition(s), usk with 2 partitions
                        time:   [447.38 µs 448.90 µs 450.43 µs]
                        change: [+2.2630% +2.6910% +3.1121%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 98 outliers among 5000 measurements (1.96%)
  86 (1.72%) high mild
  12 (0.24%) high severe
Header encryption and decryption/ciphertexts with 5 partition(s), usk with 2 partitions
                        time:   [596.58 µs 598.74 µs 600.91 µs]
                        change: [+13.733% +14.332% +14.863%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 5 outliers among 5000 measurements (0.10%)
  4 (0.08%) high mild
  1 (0.02%) high severe
Header encryption and decryption/ciphertexts with 1 partition(s), usk with 3 partitions
                        time:   [283.47 µs 283.97 µs 284.51 µs]
                        change: [+17.345% +17.560% +17.746%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 413 outliers among 5000 measurements (8.26%)
  1 (0.02%) low severe
  13 (0.26%) low mild
  279 (5.58%) high mild
  120 (2.40%) high severe
Header encryption and decryption/ciphertexts with 2 partition(s), usk with 3 partitions
                        time:   [341.43 µs 342.31 µs 343.18 µs]
                        change: [-0.4332% -0.1053% +0.2405%] (p = 0.54 > 0.05)
                        No change in performance detected.
Found 51 outliers among 5000 measurements (1.02%)
  1 (0.02%) low mild
  26 (0.52%) high mild
  24 (0.48%) high severe
Header encryption and decryption/ciphertexts with 3 partition(s), usk with 3 partitions
                        time:   [510.60 µs 512.24 µs 513.89 µs]
                        change: [+14.555% +15.096% +15.620%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 40 outliers among 5000 measurements (0.80%)
  2 (0.04%) low mild
  25 (0.50%) high mild
  13 (0.26%) high severe
Header encryption and decryption/ciphertexts with 4 partition(s), usk with 3 partitions
                        time:   [623.58 µs 626.17 µs 628.77 µs]
                        change: [+1.0322% +1.6030% +2.1662%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 10 outliers among 5000 measurements (0.20%)
  9 (0.18%) high mild
  1 (0.02%) high severe
Header encryption and decryption/ciphertexts with 5 partition(s), usk with 3 partitions
                        time:   [639.44 µs 642.20 µs 644.97 µs]
                        change: [-0.2293% +0.3589% +0.9264%] (p = 0.23 > 0.05)
                        No change in performance detected.
Found 13 outliers among 5000 measurements (0.26%)
  11 (0.22%) high mild
  2 (0.04%) high severe
Header encryption and decryption/ciphertexts with 1 partition(s), usk with 4 partitions
                        time:   [266.43 µs 266.58 µs 266.73 µs]
                        change: [+11.370% +11.451% +11.531%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 155 outliers among 5000 measurements (3.10%)
  2 (0.04%) low mild
  69 (1.38%) high mild
  84 (1.68%) high severe
Header encryption and decryption/ciphertexts with 2 partition(s), usk with 4 partitions
                        time:   [377.33 µs 378.33 µs 379.32 µs]
                        change: [+5.5998% +5.9927% +6.4036%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 3 outliers among 5000 measurements (0.06%)
  3 (0.06%) high mild
Header encryption and decryption/ciphertexts with 3 partition(s), usk with 4 partitions
                        time:   [501.50 µs 503.54 µs 505.57 µs]
                        change: [+5.7474% +6.2765% +6.7995%] (p = 0.00 < 0.05)
                        Performance has regressed.
Header encryption and decryption/ciphertexts with 4 partition(s), usk with 4 partitions
                        time:   [601.64 µs 604.36 µs 607.08 µs]
                        change: [+2.3859% +3.0427% +3.6791%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 1 outliers among 5000 measurements (0.02%)
  1 (0.02%) high mild
Header encryption and decryption/ciphertexts with 5 partition(s), usk with 4 partitions
                        time:   [713.88 µs 717.33 µs 720.75 µs]
                        change: [+0.8508% +1.5361% +2.2386%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Header encryption and decryption/ciphertexts with 1 partition(s), usk with 5 partitions
                        time:   [295.77 µs 295.88 µs 295.98 µs]
                        change: [+41.280% +41.619% +41.945%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 108 outliers among 5000 measurements (2.16%)
  4 (0.08%) low mild
  86 (1.72%) high mild
  18 (0.36%) high severe
Header encryption and decryption/ciphertexts with 2 partition(s), usk with 5 partitions
                        time:   [449.02 µs 450.37 µs 451.69 µs]
                        change: [+44.681% +45.349% +46.008%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 4 outliers among 5000 measurements (0.08%)
  4 (0.08%) high mild
Header encryption and decryption/ciphertexts with 3 partition(s), usk with 5 partitions
                        time:   [566.05 µs 568.67 µs 571.31 µs]
                        change: [+22.908% +23.708% +24.514%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 20 outliers among 5000 measurements (0.40%)
  15 (0.30%) high mild
  5 (0.10%) high severe
Header encryption and decryption/ciphertexts with 4 partition(s), usk with 5 partitions
                        time:   [828.21 µs 832.45 µs 836.71 µs]
                        change: [+37.986% +39.055% +40.164%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 8 outliers among 5000 measurements (0.16%)
  8 (0.16%) high mild
Header encryption and decryption/ciphertexts with 5 partition(s), usk with 5 partitions
                        time:   [957.45 µs 962.63 µs 967.79 µs]
                        change: [+15.806% +16.758% +17.778%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 7 outliers among 5000 measurements (0.14%)
  5 (0.10%) high mild
  2 (0.04%) high severe

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
Key serialization/MSK   time:   [4.6007 µs 4.6080 µs 4.6154 µs]
                        change: [+4.3792% +4.6585% +4.9359%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 298 outliers among 5000 measurements (5.96%)
  260 (5.20%) high mild
  38 (0.76%) high severe
Key serialization/MPK   time:   [59.024 µs 59.104 µs 59.196 µs]
                        change: [-0.7746% -0.6062% -0.4336%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 218 outliers among 5000 measurements (4.36%)
  5 (0.10%) low mild
  182 (3.64%) high mild
  31 (0.62%) high severe
Key serialization/USK 1 partition
                        time:   [365.62 ns 365.93 ns 366.25 ns]
                        change: [+0.4169% +0.6597% +0.8988%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 164 outliers among 5000 measurements (3.28%)
  119 (2.38%) high mild
  45 (0.90%) high severe

Header serialization/1 partition(s)
                        time:   [6.8348 µs 6.8388 µs 6.8428 µs]
                        change: [-1.2088% -0.9808% -0.7565%] (p = 0.00 < 0.05)
                        Change within noise threshold.
Found 124 outliers among 5000 measurements (2.48%)
  1 (0.02%) low mild
  95 (1.90%) high mild
  28 (0.56%) high severe
Header serialization/2 partition(s)
                        time:   [7.0079 µs 7.0143 µs 7.0207 µs]
                        change: [-1.5500% -1.2934% -1.0512%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 230 outliers among 5000 measurements (4.60%)
  10 (0.20%) low mild
  184 (3.68%) high mild
  36 (0.72%) high severe
Header serialization/3 partition(s)
                        time:   [7.2900 µs 7.3024 µs 7.3165 µs]
                        change: [-1.6010% -1.3878% -1.1456%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 302 outliers among 5000 measurements (6.04%)
  10 (0.20%) low mild
  239 (4.78%) high mild
  53 (1.06%) high severe
Header serialization/4 partition(s)
                        time:   [7.6489 µs 7.6592 µs 7.6709 µs]
                        change: [+1.6409% +1.8617% +2.0797%] (p = 0.00 < 0.05)
                        Performance has regressed.
Found 391 outliers among 5000 measurements (7.82%)
  1 (0.02%) low severe
  71 (1.42%) low mild
  276 (5.52%) high mild
  43 (0.86%) high severe
Header serialization/5 partition(s)
                        time:   [7.8092 µs 7.8229 µs 7.8370 µs]
                        change: [-2.2961% -2.0523% -1.8050%] (p = 0.00 < 0.05)
                        Performance has improved.
Found 612 outliers among 5000 measurements (12.24%)
  70 (1.40%) low mild
  346 (6.92%) high mild
```
