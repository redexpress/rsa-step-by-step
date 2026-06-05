#include <cassert>
#include <cstdio>
#include <cstring>

#include "rsa/rsa_engine.h"

int main() {
    rsa::RSAKey key =
        rsa::RSAEngine::generate_key();

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

    char* s = plain.to_dec();

    std::printf("plain = %s\n", s);

    assert(std::strcmp(s, "65") == 0);

    OPENSSL_free(s);

    std::printf("test passed\n");

    return 0;
}