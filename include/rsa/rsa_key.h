#ifndef RSA_KEY_H
#define RSA_KEY_H

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
    };
}

#endif