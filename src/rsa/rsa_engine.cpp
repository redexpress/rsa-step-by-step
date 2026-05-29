#include <openssl/bn.h>

#include "rsa/rsa_engine.h"

#include <openssl/rand.h>

#include "rsa/padding.h"

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

        key.p = p;
        key.q = q;
        key.dp = BigInt::mod(key.d, BigInt::subtract(p, BigInt(1)));
        key.dq = BigInt::mod(key.d, BigInt::subtract(q, BigInt(1)));
        key.qinv = BigInt::mod_inverse(q, p);

        key.set_block_size(BN_num_bytes(key.n.raw()));

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

        key.p = bp;
        key.q = bq;
        key.dp = BigInt::mod(key.d, BigInt::subtract(bp, one));
        key.dq = BigInt::mod(key.d, BigInt::subtract(bq, one));
        key.qinv = BigInt::mod_inverse(bq, bp);

        key.set_block_size(BN_num_bytes(key.n.raw()));

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

        int k = key.block_size();
        std::vector<uint8_t> em = PKCS1v15::encode(message, k);
        BigInt m = BigInt::from_bytes(em);
        BigInt c = encrypt(m, key);

        return c.to_bytes(k);
    }

    std::vector<uint8_t> RSAEngine::decrypt(
        const std::vector<uint8_t>& cipher, const RSAKey& key) {

        int k = key.block_size();
        BigInt c = BigInt::from_bytes(cipher);
        BigInt m = decrypt(c, key);
        return PKCS1v15::decode(m.to_bytes(k), k);
    }

}