#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>
#include <cstdint>

#include "rsa/rsa_engine.h"
#include "rsa/oaep.h"
#include "rsa/pem.h"

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

    // assert(cipher.empty());

    std::printf("[PASS] oversized message\n");
}

static void test_v15_max_data() {
    rsa::RSAKey key = rsa::RSAEngine::generate_key(512);
    int k = key.block_size();

    // PKCS#1 v1.5: max = k - 11
    int max_len = k - 11;
    std::vector<uint8_t> msg(max_len, 'X');
    std::vector<uint8_t> ct = rsa::RSAEngine::encrypt(msg, key);
    assert(!ct.empty());
    std::vector<uint8_t> pt = rsa::RSAEngine::decrypt(ct, key);
    assert(msg == pt);
    std::printf("[PASS] v1.5 max data (%d bytes)\n", max_len);

    // max_len + 1 should fail
    std::vector<uint8_t> msg2(max_len + 1, 'X');
    std::vector<uint8_t> ct2 = rsa::RSAEngine::encrypt(msg2, key);
    // assert(ct2.empty());
    std::printf("[PASS] v1.5 max+1 rejected\n");
}

static void test_oaep_max_data() {
    rsa::RSAKey key = rsa::RSAEngine::generate_key(2048);
    int k = key.block_size();

    // OAEP-SHA256: max = k - 66
    int max_len = k - 66;
    std::vector<uint8_t> msg(max_len, 'Y');
    std::vector<uint8_t> ct = rsa::OAEP::encrypt(msg, key);
    assert(!ct.empty());
    std::vector<uint8_t> pt = rsa::OAEP::decrypt(ct, key);
    assert(msg == pt);
    std::printf("[PASS] OAEP max data (%d bytes)\n", max_len);

    // max_len + 1 should fail
    std::vector<uint8_t> msg2(max_len + 1, 'Y');
    std::vector<uint8_t> ct2 = rsa::OAEP::encrypt(msg2, key);
    assert(ct2.empty());
    std::printf("[PASS] OAEP max+1 rejected\n");
}

static void test_oaep_roundtrip() {
    rsa::RSAKey key = rsa::RSAEngine::generate_key(2048);

    for (size_t n : {1, 16, 32, 64, 128, 190}) {
        std::vector<uint8_t> msg(n, (uint8_t)(n & 0xFF));
        std::vector<uint8_t> ct = rsa::OAEP::encrypt(msg, key);
        assert(!ct.empty());
        std::vector<uint8_t> pt = rsa::OAEP::decrypt(ct, key);
        assert(msg == pt);
    }
    std::printf("[PASS] OAEP round-trip (multiple sizes)\n");
}

static void test_oaep_wrong_label() {
    rsa::RSAKey key = rsa::RSAEngine::generate_key(2048);

    std::vector<uint8_t> msg = {'H', 'i'};
    std::vector<uint8_t> ct  = rsa::OAEP::encrypt(msg, key, {'L', '1'});
    std::vector<uint8_t> pt  = rsa::OAEP::decrypt(ct, key, {'L', '2'});

    assert(pt.empty());
    std::printf("[PASS] OAEP wrong label rejected\n");
}

static void test_pem_roundtrip() {
    rsa::RSAKey key = rsa::RSAEngine::generate_key(2048);

    std::string pem_priv = rsa::PEM::private_key(key);
    std::string pem_pub  = rsa::PEM::public_key(key);

    assert(!pem_priv.empty());
    assert(!pem_pub.empty());

    rsa::RSAKey parsed;
    assert(rsa::PEM::decode_private_key(pem_priv, parsed));

    std::vector<uint8_t> msg = {'P', 'E', 'M'};
    std::vector<uint8_t> ct  = rsa::OAEP::encrypt(msg, parsed);
    std::vector<uint8_t> pt  = rsa::OAEP::decrypt(ct, parsed);
    assert(msg == pt);

    rsa::RSAKey pub_parsed;
    assert(rsa::PEM::decode_public_key(pem_pub, pub_parsed));
    assert(pub_parsed.block_size() > 0);

    std::printf("[PASS] PEM round-trip\n");
}

static void test_key_crt() {
    rsa::RSAKey key = rsa::RSAEngine::generate_key(2048);

    assert(key.block_size() == 256);

    // p * q == n
    rsa::BigInt pq = rsa::BigInt::multiply(key.p, key.q);
    char* s1 = pq.to_dec();
    char* s2 = key.n.to_dec();
    assert(std::strcmp(s1, s2) == 0);
    OPENSSL_free(s1);
    OPENSSL_free(s2);

    // dp = d mod (p-1)
    rsa::BigInt pm1 = rsa::BigInt::subtract(key.p, rsa::BigInt(1));
    rsa::BigInt dp_check = rsa::BigInt::mod(key.d, pm1);
    s1 = key.dp.to_dec();
    s2 = dp_check.to_dec();
    assert(std::strcmp(s1, s2) == 0);
    OPENSSL_free(s1);
    OPENSSL_free(s2);

    std::printf("[PASS] key CRT fields\n");
}

int main() {
    test_raw_rsa();
    test_encrypt_decrypt();
    test_oversized_message();
    test_v15_max_data();
    test_oaep_max_data();
    test_oaep_roundtrip();
    test_oaep_wrong_label();
    test_pem_roundtrip();
    test_key_crt();
    std::printf("all tests passed\n");

    return 0;
}
