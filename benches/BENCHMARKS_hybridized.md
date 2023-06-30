# Benchmarks for Covercrypt post-quantum implementation

## Table of Contents

- [Overview](#overview)
- [Benchmark Results](#benchmark-results)
    - [Header encryption](#header-encryption)
    - [Header encryption and decryption](#header-encryption-and-decryption)
    - [Key serialization](#key-serialization)
    - [Header serialization](#header-serialization)

## Overview

This is a benchmark comparison report.

## Benchmark Results

### Header encryption

|        | `1 partition(s), 1 access`          | `2 partition(s), 1 access`          | `3 partition(s), 1 access`          | `4 partition(s), 1 access`          | `5 partition(s), 1 access`           |
|:-------|:------------------------------------|:------------------------------------|:------------------------------------|:------------------------------------|:------------------------------------ |
|        | `176.93 us` (**1.00x**)           | `266.21 us` (*1.50x slower*)      | `369.05 us` (*2.09x slower*)      | `466.62 us` (*2.64x slower*)      | `569.79 us` (*3.22x slower*)       |

### Header encryption and decryption

|        | `ciphertexts with 1 partition(s), usk with 1 partitions`          | `ciphertexts with 2 partition(s), usk with 1 partitions`          | `ciphertexts with 3 partition(s), usk with 1 partitions`          | `ciphertexts with 4 partition(s), usk with 1 partitions`          | `ciphertexts with 5 partition(s), usk with 1 partitions`          | `ciphertexts with 1 partition(s), usk with 2 partitions`          | `ciphertexts with 2 partition(s), usk with 2 partitions`          | `ciphertexts with 3 partition(s), usk with 2 partitions`          | `ciphertexts with 4 partition(s), usk with 2 partitions`          | `ciphertexts with 5 partition(s), usk with 2 partitions`          | `ciphertexts with 1 partition(s), usk with 3 partitions`          | `ciphertexts with 2 partition(s), usk with 3 partitions`          | `ciphertexts with 3 partition(s), usk with 3 partitions`          | `ciphertexts with 4 partition(s), usk with 3 partitions`          | `ciphertexts with 5 partition(s), usk with 3 partitions`          | `ciphertexts with 1 partition(s), usk with 4 partitions`          | `ciphertexts with 2 partition(s), usk with 4 partitions`          | `ciphertexts with 3 partition(s), usk with 4 partitions`          | `ciphertexts with 4 partition(s), usk with 4 partitions`          | `ciphertexts with 5 partition(s), usk with 4 partitions`          | `ciphertexts with 1 partition(s), usk with 5 partitions`          | `ciphertexts with 2 partition(s), usk with 5 partitions`          | `ciphertexts with 3 partition(s), usk with 5 partitions`          | `ciphertexts with 4 partition(s), usk with 5 partitions`          | `ciphertexts with 5 partition(s), usk with 5 partitions`           |
|:-------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------ |
|        | `309.26 us` (**1.00x**)                                         | `423.71 us` (*1.37x slower*)                                    | `550.71 us` (*1.78x slower*)                                    | `665.59 us` (*2.15x slower*)                                    | `807.60 us` (*2.61x slower*)                                    | `350.83 us` (*1.13x slower*)                                    | `501.92 us` (*1.62x slower*)                                    | `650.93 us` (*2.10x slower*)                                    | `801.53 us` (*2.59x slower*)                                    | `998.96 us` (*3.23x slower*)                                    | `304.14 us` (**1.02x faster**)                                  | `489.87 us` (*1.58x slower*)                                    | `668.58 us` (*2.16x slower*)                                    | `837.40 us` (*2.71x slower*)                                    | `1.05 ms` (*3.39x slower*)                                      | `404.11 us` (*1.31x slower*)                                    | `616.11 us` (*1.99x slower*)                                    | `827.60 us` (*2.68x slower*)                                    | `1.02 ms` (*3.31x slower*)                                      | `1.22 ms` (*3.94x slower*)                                      | `363.74 us` (*1.18x slower*)                                    | `579.54 us` (*1.87x slower*)                                    | `852.07 us` (*2.76x slower*)                                    | `1.05 ms` (*3.40x slower*)                                      | `1.32 ms` (*4.28x slower*)                                       |

### Key serialization

|        | `MSK`                    | `MPK`                            | `USK 1 partition`                  |
|:-------|:-------------------------|:---------------------------------|:---------------------------------- |
|        | `12.48 us` (**1.00x**) | `101.83 us` (*8.16x slower*)   | `900.00 ns` (**13.87x faster**)  |

### Header serialization

|        | `1 partition(s)`          | `2 partition(s)`                | `3 partition(s)`                | `4 partition(s)`                | `5 partition(s)`                 |
|:-------|:--------------------------|:--------------------------------|:--------------------------------|:--------------------------------|:-------------------------------- |
|        | `10.55 us` (**1.00x**)  | `11.62 us` (**1.10x slower**) | `12.03 us` (*1.14x slower*)   | `12.91 us` (*1.22x slower*)   | `13.27 us` (*1.26x slower*)    |

---
Made with [criterion-table](https://github.com/nu11ptr/criterion-table)
