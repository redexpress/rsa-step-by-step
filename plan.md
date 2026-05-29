# RSA Project Roadmap

Goal:

```text
Build a real RSA library step-by-step,
from educational implementation
to industrial-grade cryptography.
```

Language:

```text
C++ 17
```

Style:

```text
C with classes
```

Meaning:

* RAII is allowed
* Small wrappers are allowed
* Minimal templates
* Minimal inheritance
* Avoid "clever C++"
* Focus on cryptography engineering

External dependency (early stages):

```text
OpenSSL BIGNUM only
```

NOT:

* OpenSSL RSA API
* EVP API
* OpenSSL PEM helpers

You implement the RSA logic yourself.

---

# 0. Project Philosophy

The project is divided into layers.

Do NOT build everything inside one RSA class.

Recommended architecture:

| Module  | Responsibility                  |
| ------- | ------------------------------- |
| bigint  | Big integer abstraction         |
| rsa     | RSA math and key operations     |
| padding | PKCS1/OAEP/PSS                  |
| asn1    | DER encoding                    |
| pem     | PEM serialization               |
| hash    | SHA256 etc                      |
| random  | Secure randomness               |
| tests   | Validation and interoperability |

---

# 1. Repository Layout

This layout should remain stable across all versions.

```text
/
├── CMakeLists.txt
├── cmake/
├── include/
│   └── rsa/
│       ├── bigint.h
│       ├── rsa_key.h
│       ├── rsa_engine.h
│       ├── padding.h
│       ├── oaep.h
│       ├── pss.h
│       ├── pem.h
│       ├── der.h
│       ├── asn1.h
│       ├── hash.h
│       ├── random.h
│       └── error.h
│
├── src/
│   ├── bigint/
│   ├── rsa/
│   ├── padding/
│   ├── pem/
│   ├── der/
│   ├── asn1/
│   ├── hash/
│   ├── random/
│   └── util/
│
├── tests/
├── examples/
├── benchmark/
├── fuzz/
└── docs/
```

---

# 2. Version v0 — Minimal Raw RSA

# Goal

Implement the mathematical core of RSA.

Encryption:

c = m^e \bmod n

Decryption:

m = c^d \bmod n

---

# Features

* RSA key generation
* Raw encryption/decryption
* OpenSSL BIGNUM backend
* Integer-only interface
* No padding
* No PEM
* No byte arrays

---

# Main Tasks

## bigint module

Create a thin wrapper around:

```text
OpenSSL BIGNUM
```

Responsibilities:

* allocation/free
* copy/move
* modular exponentiation
* modular inverse
* multiplication
* comparison

---

## rsa module

Implement:

* prime generation
* modulus generation
* Euler totient
* public exponent selection
* private exponent calculation

---

## tests

Verify:

```text
decrypt(encrypt(m)) == m
```

for random messages.

---

# Completion Criteria

You can:

* generate RSA keys
* encrypt integers
* decrypt integers
* interoperate mathematically with OpenSSL

---

# 3. Version v1 — Byte-Oriented RSA

# Goal

Support binary data instead of integers.

---

# Features

* byte array interface
* integer/byte conversion
* message size validation
* binary-safe APIs

---

# Main Tasks

## serialization layer

Implement:

* bytes → BigInt
* BigInt → bytes

---

## rsa interface redesign

Public API should operate on:

```text
std::vector<uint8_t>
```

instead of raw BIGNUMs.

---

## validation

Reject messages where:

```text
m >= n
```

---

# Completion Criteria

You can:

* encrypt binary messages
* decrypt binary messages
* correctly reject oversized messages

---

# 4. Version v2 — PKCS#1 v1.5 Padding

# Goal

Make RSA practically usable.

---

# Features

Implement:

```text
EME-PKCS1-v1_5
```

---

# Main Tasks

## padding module

Implement:

```text
00 02 random_padding 00 message
```

---

## secure randomness

Introduce secure random byte generation.

---

## RSA integration

Encryption flow becomes:

```text
message
→ padding
→ RSA encryption
→ ciphertext
```

---

# Completion Criteria

The library:

* no longer performs deterministic RSA
* interoperates with OpenSSL PKCS#1 v1.5 encryption
* rejects invalid padding

---

# 5. Version v3 — PEM / DER / ASN.1

# Goal

Support standard RSA key formats.

---

# Features

* DER encoding
* ASN.1 serialization
* PEM export/import
* OpenSSL interoperability

---

# Main Tasks

## ASN.1 module

Implement:

* INTEGER
* SEQUENCE
* BIT STRING
* OBJECT IDENTIFIER

---

## DER encoder

Implement binary DER serialization.

---

## PEM layer

Implement:

```text
Base64 + BEGIN/END wrappers
```

---

# Completion Criteria

Generated keys can be:

* loaded by OpenSSL
* exported as PEM
* parsed back into your library

---

# 6. Version v4 — CRT Optimization

# Goal

Reach realistic RSA performance.

---

# Features

Store CRT parameters:

* p
* q
* dp
* dq
* qinv

---

# Main Tasks

## key generation

Compute CRT values during key generation.

---

## optimized decryption

Replace:

m = c^d \bmod n

with CRT-based reconstruction.

---

# Completion Criteria

Decryption/signing becomes significantly faster.

Expected improvement:

```text
3x to 8x
```

---

# 7. Version v5 — OAEP

# Goal

Implement modern RSA encryption padding.

---

# Features

* OAEP encoding
* MGF1
* SHA256 support

---

# Main Tasks

## hash module

Introduce:

* SHA256 abstraction
* digest APIs

---

## OAEP implementation

Implement:

* seed generation
* mask generation
* XOR masking
* OAEP block layout

---

# Completion Criteria

The library interoperates with:

```text
RSA-OAEP-SHA256
```

implementations.

---

# 8. Version v6 — RSA Signatures / PSS

# Goal

Support RSA signing.

---

# Features

* PKCS#1 v1.5 signatures
* RSA-PSS signatures

---

# Main Tasks

## signature engine

Implement:

```text
hash
→ encoding
→ modular exponentiation
```

---

## PSS module

Implement:

* MGF1
* salt handling
* randomized signatures

---

# Completion Criteria

Generated signatures verify in OpenSSL.

---

# 9. Version v7 — Custom Big Integer Library

# Goal

Remove OpenSSL BIGNUM dependency.

---

# Features

Own bigint implementation.

---

# Main Tasks

## bigint core

Implement:

* add/sub
* multiply
* divide
* modulo
* comparison
* shifts

---

## modular arithmetic

Implement:

* modular multiplication
* modular exponentiation
* modular inverse

---

## performance algorithms

Introduce:

* Montgomery reduction
* Karatsuba multiplication

---

# Completion Criteria

RSA works entirely without OpenSSL BN.

---

# 10. Version v8 — Constant-Time Cryptography

# Goal

Mitigate side-channel attacks.

---

# Features

Constant-time execution paths.

---

# Main Tasks

Remove:

* secret-dependent branches
* secret-dependent memory access
* timing leaks

---

## RSA blinding

Introduce randomized exponentiation blinding.

---

# Completion Criteria

The implementation avoids obvious timing attacks.

---

# 11. Version v9 — Industrial-Grade RSA

# Goal

Become production-quality.

---

# Features

* DRBG
* entropy subsystem
* fault attack mitigations
* fuzz testing
* benchmark suite
* interoperability suite

---

# Main Tasks

## randomness subsystem

Implement:

* secure entropy collection
* deterministic random generator

---

## robustness

Add:

* fuzzing
* malformed ASN.1 handling
* invalid padding resistance

---

## interoperability

Test against:

* OpenSSL
* Botan
* Crypto++

---

# Completion Criteria

The library is stable, portable, and secure enough for real integration.

---

# 12. Recommended Development Strategy

# Early Stage

Focus on:

```text
v0 → v4
```

This already teaches:

* RSA internals
* key generation
* CRT
* ASN.1
* PEM
* real-world interoperability

---

# Middle Stage

Focus on:

```text
OAEP + PSS
```

This teaches real cryptographic engineering.

---

# Advanced Stage

Only then begin:

```text
custom bigint
constant-time
```

Those are the hardest parts of cryptography implementation.

---

# 13. Build System

Recommended minimum CMake:

```cmake
cmake_minimum_required(VERSION 3.16)

project(rsa LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)

add_library(rsa STATIC
    src/rsa/rsa_engine.cpp
    src/rsa/keygen.cpp
    src/bigint/openssl_bn.cpp
)

target_include_directories(rsa PUBLIC include)

target_link_libraries(rsa OpenSSL::Crypto)
```

---

# 14. Testing Strategy

Every version should include:

| Test Type                | Purpose          |
| ------------------------ | ---------------- |
| unit tests               | correctness      |
| OpenSSL interoperability | compatibility    |
| randomized tests         | robustness       |
| benchmark tests          | performance      |
| fuzz tests               | parser hardening |

---

# 15. Final Philosophy

The difficult part of RSA is NOT:

```text
c = m^e mod n
```

The difficult parts are:

* padding
* ASN.1
* randomness
* side-channel resistance
* bigint arithmetic
* interoperability
* engineering discipline

That is what transforms: an RSA demo into a cryptographic library
