#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>
#include <cstdint>

#include "rsa/rsa_engine.h"

static void test_raw_rsa() {
    rsa::RSAKey key = rsa::RSAEngine::generate_key(512);

    rsa::BigInt message(65);

    rsa::BigInt cipher = rsa::RSAEngine::encrypt(message, key);
    rsa::BigInt plain = rsa::RSAEngine::decrypt(cipher, key);

    char* s = plain.to_dec();

    std::printf("plain = %s\n", s);

    assert(std::strcmp(s, "65") == 0);

    OPENSSL_free(s);

    std::printf("[PASS] raw rsa\n");
}

static void test_encrypt_decrypt() {
    rsa::RSAKey key = rsa::RSAEngine::generate_key(512);

    std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o'};

    std::vector<uint8_t> cipher = rsa::RSAEngine::encrypt(message, key);
    std::vector<uint8_t> plain = rsa::RSAEngine::decrypt(cipher, key);

    assert(message == plain);

    std::printf("[PASS] encrypt/decrypt\n");
}

static void test_oversized_message() {
    rsa::RSAKey key = rsa::RSAEngine::generate_key(512);

    std::vector<uint8_t> message(1000, 'A');

    std::vector<uint8_t> cipher = rsa::RSAEngine::encrypt(message, key);

    assert(cipher.empty());

    std::printf("[PASS] oversized message\n");
}

int main() {
    test_raw_rsa();
    test_encrypt_decrypt();
    test_oversized_message();
    std::printf("all tests passed\n");

    return 0;
}