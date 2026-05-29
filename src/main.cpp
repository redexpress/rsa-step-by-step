#include <cstdio>
#include <cstring>
#include <openssl/bn.h>
#include <openssl/crypto.h>

#include "rsa/rsa_engine.h"
#include "rsa/padding.h"
#include "rsa/pem.h"

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

void version2() {
    rsa::RSAKey key = rsa::RSAEngine::generate_key(512);
    key.print();
    std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o'};
    std::vector<uint8_t> cipher = rsa::RSAEngine::encrypt(message, key);  // high-level encrypt (includes padding internally)
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


void version3() {
    rsa::RSAKey key = rsa::RSAEngine::generate_key(512);

    std::string pem_priv = rsa::PEM::private_key(key);
    std::string pem_pub  = rsa::PEM::public_key(key);

    std::printf("=== PEM private key ===\n%s", pem_priv.c_str());
    std::printf("=== PEM public key ===\n%s", pem_pub.c_str());

    rsa::RSAKey parsed;
    if (!rsa::PEM::decode_private_key(pem_priv, parsed)) {
        std::printf("FAIL: decode private key\n");
        return;
    }

    std::vector<uint8_t> msg = {'H', 'e', 'l', 'l', 'o'};
    std::vector<uint8_t> ct  = rsa::RSAEngine::encrypt(msg, parsed);
    std::vector<uint8_t> pt  = rsa::RSAEngine::decrypt(ct, parsed);

    std::printf("plain = ");
    for (uint8_t b : pt) std::printf("%c", b);
    std::printf("\n");

    rsa::RSAKey pub_parsed;
    if (!rsa::PEM::decode_public_key(pem_pub, pub_parsed)) {
        std::printf("FAIL: decode public key\n");
        return;
    }
    std::printf("public key parsed OK, n mod size = %d bytes\n",
                pub_parsed.block_size());
}

int main() {
    version2();
    version3();
    return 0;
}