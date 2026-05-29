#ifndef RSA_ENGINE_H
#define RSA_ENGINE_H

#include "rsa/bigint.h"
#include "rsa/rsa_key.h"
#include <vector>
#include <cstdint>

namespace rsa {

    class RSAEngine {
    public:
        static RSAKey generate_key();
        static RSAKey generate_key(int bits);

        static BigInt encrypt(
            const BigInt& message,
            const RSAKey& key
        );

        static BigInt decrypt(
            const BigInt& cipher,
            const RSAKey& key
        );

        static std::vector<uint8_t> encrypt(
            const std::vector<uint8_t>& message, const RSAKey& key
        );

        static std::vector<uint8_t> decrypt(
            const std::vector<uint8_t>& cipher, const RSAKey& key
        );
    };



}

#endif
