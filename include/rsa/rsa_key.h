#ifndef RSA_KEY_H
#define RSA_KEY_H

#include <openssl/bn.h>

#include "rsa/bigint.h"

namespace rsa {

    class RSAKey {
    public:
        BigInt n;
        BigInt e;
        BigInt d;

        RSAKey();

        RSAKey(
            const BigInt& n,
            const BigInt& e,
            const BigInt& d
        );

        void print() const;

        int block_size() const;

    public:
        void set_block_size(int k) { k_ = k; }

    private:
        int k_;
    };
}

#endif