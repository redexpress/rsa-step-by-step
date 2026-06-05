# rsa-step-by-step

A step-by-step RSA implementation project in C++17, from raw RSA to real cryptographic engineering.

## Version

Current version:

```text
v0 - Raw RSA
```

## Features

* OpenSSL BIGNUM backend
* Minimal BigInt wrapper
* RSA key generation
* RSA encryption/decryption
* Public/private key structure
* Simple key printing
* CMake build system

## Current Scope

This version intentionally implements only raw RSA mathematics:

c = m^e \bmod n

m = c^d \bmod n

Not implemented yet:

* PKCS#1 padding
* OAEP
* PSS
* PEM/DER
* ASN.1
* CRT optimization
* custom bigint
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
* learning cryptographic engineering
* building RSA incrementally
* keeping the implementation simple and educational
