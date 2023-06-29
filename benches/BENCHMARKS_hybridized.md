# Benchmarks for Covercrypt post-quantum implementation

## Table of Contents

- [Benchmark Results](#benchmark-results)
  - [Header encryption](#header-encryption)
  - [Header encryption + decryption](#header-encryption-and-decryption)
  - [Key serialization](#key-serialization)
  - [Header serialization](#header-serialization)

## Benchmark Results

### Header encryption

|   | `1 partition(s), 1 access` | `2 partition(s), 1 access`   | `3 partition(s), 1 access`   | `4 partition(s), 1 access`   | `5 partition(s), 1 access` |
|:--|:---------------------------|:-----------------------------|:-----------------------------|:-----------------------------|:---------------------------|
|   | `361.16 us` (✅ **1.00x**)  | `508.30 us` (*1.41x slower*) | `693.84 us` (*1.92x slower*) | `851.50 us` (*2.36x slower*) | `1.01 ms` (*2.79x slower*) |

### Header encryption and decryption

|   | `ciphertexts with 1 partition(s), usk with 1 partitions` | `ciphertexts with 2 partition(s), usk with 1 partitions` | `ciphertexts with 3 partition(s), usk with 1 partitions` | `ciphertexts with 4 partition(s), usk with 1 partitions` | `ciphertexts with 5 partition(s), usk with 1 partitions` | `ciphertexts with 1 partition(s), usk with 2 partitions` | `ciphertexts with 2 partition(s), usk with 2 partitions` | `ciphertexts with 3 partition(s), usk with 2 partitions` | `ciphertexts with 4 partition(s), usk with 2 partitions` | `ciphertexts with 5 partition(s), usk with 2 partitions` | `ciphertexts with 1 partition(s), usk with 3 partitions` | `ciphertexts with 2 partition(s), usk with 3 partitions` | `ciphertexts with 3 partition(s), usk with 3 partitions` | `ciphertexts with 4 partition(s), usk with 3 partitions` | `ciphertexts with 5 partition(s), usk with 3 partitions` |
|:--|:---------------------------------------------------------|:---------------------------------------------------------|:---------------------------------------------------------|:---------------------------------------------------------|:---------------------------------------------------------|:---------------------------------------------------------|:---------------------------------------------------------|:---------------------------------------------------------|:---------------------------------------------------------|:---------------------------------------------------------|:---------------------------------------------------------|:---------------------------------------------------------|:---------------------------------------------------------|:---------------------------------------------------------|:---------------------------------------------------------|
|   | `619.88 us` (✅ **1.00x**)                                | `831.79 us` (*1.34x slower*)                             | `1.03 ms` (*1.67x slower*)                               | `1.25 ms` (*2.01x slower*)                               | `1.43 ms` (*2.31x slower*)                               | `721.10 us` (*1.16x slower*)                             | `973.00 us` (*1.57x slower*)                             | `1.22 ms` (*1.97x slower*)                               | `1.52 ms` (*2.45x slower*)                               | `1.76 ms` (*2.84x slower*)                               | `810.82 us` (*1.31x slower*)                             | `1.11 ms` (*1.80x slower*)                               | `1.43 ms` (*2.30x slower*)                               | `1.73 ms` (*2.79x slower*)                               | `2.04 ms` (*3.30x slower*)                               |

### Key serialization

|   | `MSK`                     | `MPK`                        | `USK 1 partition`                 |
|:--|:--------------------------|:-----------------------------|:----------------------------------|
|   | `978.19 ns` (✅ **1.00x**) | `86.63 us` (*88.56x slower*) | `141.37 ns` (**6.92x faster**) |

### Header serialization

|   | `1 partition(s)`         | `2 partition(s)`                | `3 partition(s)`                | `4 partition(s)`                | `5 partition(s)`                |
|:--|:-------------------------|:--------------------------------|:--------------------------------|:--------------------------------|:--------------------------------|
|   | `12.51 us` (✅ **1.00x**) | `12.28 us` (✅ **1.02x faster**) | `12.48 us` (✅ **1.00x faster**) | `12.46 us` (✅ **1.00x faster**) | `12.46 us` (✅ **1.00x faster**) |

---
Made with [criterion-table](https://github.com/nu11ptr/criterion-table)
