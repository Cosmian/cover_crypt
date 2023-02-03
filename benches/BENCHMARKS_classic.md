# Benchmarks for CoverCrypt: classic implementation (pre-quantum)

## Table of Contents

- [Benchmark Results](#benchmark-results)
    - [Header encryption](#header-encryption)
    - [Header encryption + decryption](#header-encryption-+-decryption)
    - [Key serialization](#key-serialization)
    - [Header serialization](#header-serialization)

## Benchmark Results

### Header encryption

|        | `1 partition(s), 1 access`          | `2 partition(s), 1 access`          | `3 partition(s), 1 access`          | `4 partition(s), 1 access`          | `5 partition(s), 1 access`           |
|:-------|:------------------------------------|:------------------------------------|:------------------------------------|:------------------------------------|:------------------------------------ |
|        | `293.43 us` (✅ **1.00x**)           | `367.53 us` (*1.25x slower*)      | `450.77 us` (*1.54x slower*)      | `588.11 us` (*2.00x slower*)      | `627.62 us` (*2.14x slower*)       |

### Header encryption + decryption

|        | `ciphertexts with 1 partition(s), usk with 1 partitions`          | `ciphertexts with 2 partition(s), usk with 1 partitions`          | `ciphertexts with 3 partition(s), usk with 1 partitions`          | `ciphertexts with 4 partition(s), usk with 1 partitions`          | `ciphertexts with 5 partition(s), usk with 1 partitions`          | `ciphertexts with 1 partition(s), usk with 2 partitions`          | `ciphertexts with 2 partition(s), usk with 2 partitions`          | `ciphertexts with 3 partition(s), usk with 2 partitions`          | `ciphertexts with 4 partition(s), usk with 2 partitions`          | `ciphertexts with 5 partition(s), usk with 2 partitions`          | `ciphertexts with 1 partition(s), usk with 3 partitions`          | `ciphertexts with 2 partition(s), usk with 3 partitions`          | `ciphertexts with 3 partition(s), usk with 3 partitions`          | `ciphertexts with 4 partition(s), usk with 3 partitions`          | `ciphertexts with 5 partition(s), usk with 3 partitions`           |
|:-------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------ |
|        | `491.23 us` (✅ **1.00x**)                                         | `632.31 us` (*1.29x slower*)                                    | `752.58 us` (*1.53x slower*)                                    | `876.77 us` (*1.78x slower*)                                    | `1.04 ms` (*2.12x slower*)                                      | `487.07 us` (✅ **1.01x faster**)                                  | `662.65 us` (*1.35x slower*)                                    | `852.29 us` (*1.74x slower*)                                    | `1.01 ms` (*2.06x slower*)                                      | `1.16 ms` (*2.37x slower*)                                      | `565.50 us` (*1.15x slower*)                                    | `795.23 us` (*1.62x slower*)                                    | `1.01 ms` (*2.05x slower*)                                      | `1.22 ms` (*2.48x slower*)                                      | `1.43 ms` (*2.91x slower*)                                       |

### Key serialization

|        | `MSK`                     | `MPK`                             | `USK 1 partition`                |
|:-------|:--------------------------|:----------------------------------|:-------------------------------- |
|        | `443.45 ns` (✅ **1.00x**) | `85.07 us` (*191.84x slower*)   | `58.34 ns` (🚀 **7.60x faster**)  |

### Header serialization

|        | `1 partition(s)`          | `2 partition(s)`                | `3 partition(s)`                | `4 partition(s)`                | `5 partition(s)`                 |
|:-------|:--------------------------|:--------------------------------|:--------------------------------|:--------------------------------|:-------------------------------- |
|        | `12.15 us` (✅ **1.00x**)  | `12.20 us` (✅ **1.00x slower**) | `12.16 us` (✅ **1.00x slower**) | `12.19 us` (✅ **1.00x slower**) | `12.13 us` (✅ **1.00x faster**)  |

---
Made with [criterion-table](https://github.com/nu11ptr/criterion-table)
