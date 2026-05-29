#include <cstdio>
#include <openssl/bn.h>
#include <openssl/crypto.h>

#include "rsa/rsa_key.h"

namespace rsa {

    RSAKey::RSAKey() : k_(0) {
    }

    RSAKey::RSAKey(
        const BigInt& n,
        const BigInt& e,
        const BigInt& d
    ) {
        this->n = n;
        this->e = e;
        this->d = d;
        this->k_ = BN_num_bytes(n.raw());
    }

    void RSAKey::print() const {
        char* n_str = n.to_dec();
        char* e_str = e.to_dec();
        char* d_str = d.to_dec();

        std::printf("n = %s\n", n_str);
        std::printf("e = %s\n", e_str);
        std::printf("d = %s\n", d_str);

        OPENSSL_free(n_str);
        OPENSSL_free(e_str);
        OPENSSL_free(d_str);
    }

    int RSAKey::block_size() const {
        return k_;
    }

}