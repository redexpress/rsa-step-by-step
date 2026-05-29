#ifndef BIGINT_H
#define BIGINT_H

#include <openssl/bn.h>
#include <vector>
#include <cstdint>

namespace rsa {

    class BigInt {
    public:
        BigInt();

        explicit BigInt(unsigned long value);

        BigInt(const BigInt& other);

        BigInt& operator=(const BigInt& other);

        BigInt(BigInt&& other);

        BigInt& operator=(BigInt&& other);

        ~BigInt();

        char* to_dec() const;

        BIGNUM* raw() const;

        static BigInt multiply(
            const BigInt& a,
            const BigInt& b
        );

        static BigInt subtract(
            const BigInt& a,
            const BigInt& b
        );

        static BigInt mod_exp(
            const BigInt& base,
            const BigInt& exp,
            const BigInt& mod
        );

        static BigInt mod_inverse(
            const BigInt& a,
            const BigInt& mod
        );

        static BigInt from_bytes(
            const std::vector<uint8_t>& bytes
        );

        std::vector<uint8_t> to_bytes() const;
        std::vector<uint8_t> to_bytes(size_t min_size) const;

    private:
        BIGNUM* bn_;
    };

}

#endif

