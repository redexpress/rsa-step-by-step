#include <cstdio>
#include <openssl/crypto.h>

#include "rsa/rsa_engine.h"

void version0() {
    rsa::RSAKey key = rsa::RSAEngine::generate_key();
    key.print();

    rsa::BigInt message(65);

    rsa::BigInt cipher = rsa::RSAEngine::encrypt(message, key);

    rsa::BigInt plain = rsa::RSAEngine::decrypt(cipher, key);

    char *c = cipher.to_dec();
    char *p = plain.to_dec();

    std::printf("cipher = %s\n", c);
    std::printf("plain  = %s\n", p);

    OPENSSL_free(c);
    OPENSSL_free(p);
}

void version1() {
    rsa::RSAKey key = rsa::RSAEngine::generate_key(512);
    key.print();
    std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o'};
    std::vector<uint8_t> cipher = rsa::RSAEngine::encrypt(message, key);
    std::vector<uint8_t> plain = rsa::RSAEngine::decrypt(cipher, key);
    std::printf("cipher = ");

    for (uint8_t b : cipher) {
        std::printf("%02x", b);
    }

    std::printf("\n");
    std::printf("plain = ");

    for (uint8_t b : plain) {
        std::printf("%c", b);
    }
    std::printf("\n");
}

int main() {
    version1();
    return 0;
}