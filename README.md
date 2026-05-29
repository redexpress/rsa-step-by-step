# rsa-step-by-step

A step-by-step RSA implementation project in C++17, from raw RSA to real cryptographic engineering.

## Version

Current version:

```text
v1 - Byte-Oriented RSA
````

## Features

* OpenSSL BIGNUM backend
* BigInt wrapper
* RSA key generation (real primes)
* RSA encryption/decryption
* Byte-oriented API (std::vector<uint8_t>)
* bytes <-> BigInt conversion
* message size validation (m < n)
* unit tests
* CMake build system

## Current Scope

This version extends raw RSA to support real binary data.

RSA core:

c = m^e \bmod n

m = c^d \bmod n

Added in v1:

* binary input/output API
* BigInt serialization (bytes <-> bigint)
* oversized message rejection
* real key generation with BN_generate_prime_ex

Not implemented yet:

* PKCS#1 padding
* OAEP
* PSS
* PEM/DER
* ASN.1
* CRT optimization
* constant-time protection

## Build

```bash
mkdir build
cd build

cmake ..
make
```

## Run

```bash
./rsa
```

Example output:

```text
n = 3233
e = 17
d = 2753

cipher = 2790
plain  = 65
```

## Project Structure

```text
include/
    public headers

src/
    implementation

tests/
    future unit tests

```

## Goals

This project focuses on:

* understanding RSA internals
* moving from math RSA to data RSA
* implementing binary-safe cryptographic APIs
* keeping implementation simple and incremental

