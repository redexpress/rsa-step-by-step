#ifndef RSA_ENGINE_H
#define RSA_ENGINE_H

#include "rsa/bigint.h"
#include "rsa/rsa_key.h"

namespace rsa {

    class RSAEngine {
    public:
        static RSAKey generate_key();

        static BigInt encrypt(
            const BigInt& message,
            const RSAKey& key
        );

        static BigInt decrypt(
            const BigInt& cipher,
            const RSAKey& key
        );
    };

}

#endif
