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

        BigInt phi = BigInt::multiply(p1, q1);

        key.e = BigInt(17);
        key.d = BigInt::mod_inverse(key.e, phi);

        return key;
    }

    RSAKey RSAEngine::generate_key(int bits) {
        RSAKey key;

        BN_CTX* ctx = BN_CTX_new();
        BIGNUM* p = BN_new();
        BIGNUM* q = BN_new();

        BN_generate_prime_ex(p, bits / 2, 0, nullptr, nullptr, nullptr);
        BN_generate_prime_ex(q, bits / 2, 0, nullptr, nullptr, nullptr);

        BigInt bp;
        BigInt bq;

        BN_copy(bp.raw(), p);
        BN_copy(bq.raw(), q);

        key.n = BigInt::multiply(bp, bq);

        BigInt one(1);
        BigInt p1 = BigInt::subtract(bp, one);
        BigInt q1 = BigInt::subtract(bq, one);
        BigInt phi = BigInt::multiply(p1, q1);
        key.e = BigInt(65537);
        key.d = BigInt::mod_inverse(key.e, phi);

        BN_free(p);
        BN_free(q);
        BN_CTX_free(ctx);

        return key;
    }

    BigInt RSAEngine::encrypt(const BigInt& message, const RSAKey& key) {
        return BigInt::mod_exp(message, key.e, key.n);
    }

    BigInt RSAEngine::decrypt(const BigInt& cipher, const RSAKey& key) {
        return BigInt::mod_exp(cipher, key.d, key.n);
    }

    std::vector<uint8_t> RSAEngine::encrypt(
        const std::vector<uint8_t>& message, const RSAKey& key) {

        BigInt m = BigInt::from_bytes(message);

        if (BN_cmp(m.raw(), key.n.raw()) >= 0) {
            return {};
        }

        BigInt c = encrypt(m, key);
        return c.to_bytes();
    }

    std::vector<uint8_t> RSAEngine::decrypt(
        const std::vector<uint8_t>& cipher, const RSAKey& key) {

        BigInt c = BigInt::from_bytes(cipher);

        BigInt m = decrypt(c, key);
        return m.to_bytes();
    }

}