#include <cstdio>
#include <openssl/crypto.h>

#include "rsa/rsa_engine.h"

int main() {
    rsa::RSAKey key = rsa::RSAEngine::generate_key();
    key.print();

    rsa::BigInt message(65);

    rsa::BigInt cipher =
        rsa::RSAEngine::encrypt(
            message,
            key
        );

    rsa::BigInt plain =
        rsa::RSAEngine::decrypt(
            cipher,
            key
        );

    char* c = cipher.to_dec();
    char* p = plain.to_dec();

    std::printf("cipher = %s\n", c);
    std::printf("plain  = %s\n", p);

    OPENSSL_free(c);
    OPENSSL_free(p);

    return 0;
}