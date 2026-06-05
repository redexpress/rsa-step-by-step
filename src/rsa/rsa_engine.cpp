#include <openssl/bn.h>

#include "rsa/rsa_engine.h"

namespace rsa {

    RSAKey RSAEngine::generate_key() {
        RSAKey key;

        BigInt p(61);
        BigInt q(53);

        key.n = BigInt::multiply(p, q);

        BigInt p1 = BigInt::subtract(p, BigInt(1));
        BigInt q1 = BigInt::subtract(q, BigInt(1));

        BigInt phi =
            BigInt::multiply(p1, q1);

        key.e = BigInt(17);

        key.d =
            BigInt::mod_inverse(key.e, phi);

        return key;
    }

    BigInt RSAEngine::encrypt(
        const BigInt& message,
        const RSAKey& key
    ) {
        return BigInt::mod_exp(
            message,
            key.e,
            key.n
        );
    }

    BigInt RSAEngine::decrypt(
        const BigInt& cipher,
        const RSAKey& key
    ) {
        return BigInt::mod_exp(
            cipher,
            key.d,
            key.n
        );
    }

}