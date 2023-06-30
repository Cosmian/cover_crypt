# Benchmarks for Covercrypt: classic implementation (pre-quantum)

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
|        | `133.32 us` (✅ **1.00x**)           | `182.22 us` (❌ *1.37x slower*)      | `230.37 us` (❌ *1.73x slower*)      | `278.18 us` (❌ *2.09x slower*)      | `335.55 us` (❌ *2.52x slower*)       |

### Header encryption and decryption

|        | `ciphertexts with 1 partition(s), usk with 1 partitions`          | `ciphertexts with 2 partition(s), usk with 1 partitions`          | `ciphertexts with 3 partition(s), usk with 1 partitions`          | `ciphertexts with 4 partition(s), usk with 1 partitions`          | `ciphertexts with 5 partition(s), usk with 1 partitions`          | `ciphertexts with 1 partition(s), usk with 2 partitions`          | `ciphertexts with 2 partition(s), usk with 2 partitions`          | `ciphertexts with 3 partition(s), usk with 2 partitions`          | `ciphertexts with 4 partition(s), usk with 2 partitions`          | `ciphertexts with 5 partition(s), usk with 2 partitions`          | `ciphertexts with 1 partition(s), usk with 3 partitions`          | `ciphertexts with 2 partition(s), usk with 3 partitions`          | `ciphertexts with 3 partition(s), usk with 3 partitions`          | `ciphertexts with 4 partition(s), usk with 3 partitions`          | `ciphertexts with 5 partition(s), usk with 3 partitions`          | `ciphertexts with 1 partition(s), usk with 4 partitions`          | `ciphertexts with 2 partition(s), usk with 4 partitions`          | `ciphertexts with 3 partition(s), usk with 4 partitions`          | `ciphertexts with 4 partition(s), usk with 4 partitions`          | `ciphertexts with 5 partition(s), usk with 4 partitions`          | `ciphertexts with 1 partition(s), usk with 5 partitions`          | `ciphertexts with 2 partition(s), usk with 5 partitions`          | `ciphertexts with 3 partition(s), usk with 5 partitions`          | `ciphertexts with 4 partition(s), usk with 5 partitions`          | `ciphertexts with 5 partition(s), usk with 5 partitions`           |
|:-------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------|:------------------------------------------------------------------ |
|        | `236.02 us` (✅ **1.00x**)                                         | `293.92 us` (❌ *1.25x slower*)                                    | `356.80 us` (❌ *1.51x slower*)                                    | `419.65 us` (❌ *1.78x slower*)                                    | `480.53 us` (❌ *2.04x slower*)                                    | `229.46 us` (✅ **1.03x faster**)                                  | `310.51 us` (❌ *1.32x slower*)                                    | `406.11 us` (❌ *1.72x slower*)                                    | `484.32 us` (❌ *2.05x slower*)                                    | `565.05 us` (❌ *2.39x slower*)                                    | `227.64 us` (✅ **1.04x faster**)                                  | `339.10 us` (❌ *1.44x slower*)                                    | `450.91 us` (❌ *1.91x slower*)                                    | `543.62 us` (❌ *2.30x slower*)                                    | `645.11 us` (❌ *2.73x slower*)                                    | `312.85 us` (❌ *1.33x slower*)                                    | `446.54 us` (❌ *1.89x slower*)                                    | `572.54 us` (❌ *2.43x slower*)                                    | `689.37 us` (❌ *2.92x slower*)                                    | `810.78 us` (❌ *3.44x slower*)                                    | `231.57 us` (✅ **1.02x faster**)                                  | `375.80 us` (❌ *1.59x slower*)                                    | `527.09 us` (❌ *2.23x slower*)                                    | `661.97 us` (❌ *2.80x slower*)                                    | `814.49 us` (❌ *3.45x slower*)                                     |

### Key serialization

|        | `MSK`                     | `MPK`                             | `USK 1 partition`                 |
|:-------|:--------------------------|:----------------------------------|:--------------------------------- |
|        | `801.07 ns` (✅ **1.00x**) | `83.76 us` (❌ *104.55x slower*)   | `118.50 ns` (🚀 **6.76x faster**)  |

### Header serialization

|        | `1 partition(s)`          | `2 partition(s)`                | `3 partition(s)`                | `4 partition(s)`                | `5 partition(s)`                 |
|:-------|:--------------------------|:--------------------------------|:--------------------------------|:--------------------------------|:-------------------------------- |
|        | `10.27 us` (✅ **1.00x**)  | `10.25 us` (✅ **1.00x faster**) | `10.40 us` (✅ **1.01x slower**) | `10.41 us` (✅ **1.01x slower**) | `10.53 us` (✅ **1.02x slower**)  |

---
Made with [criterion-table](https://github.com/nu11ptr/criterion-table)
