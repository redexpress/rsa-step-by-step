#include "rsa/bigint.h"

namespace rsa {

BigInt::BigInt() { bn_ = BN_new(); }

BigInt::BigInt(unsigned long v) { bn_ = BN_new(); BN_set_word(bn_, v); }

BigInt::BigInt(const BigInt& o) { bn_ = BN_dup(o.bn_); }

BigInt& BigInt::operator=(const BigInt& o) {
    if (this != &o) { BN_free(bn_); bn_ = BN_dup(o.bn_); }
    return *this;
}

BigInt::BigInt(BigInt&& o) : bn_(o.bn_) { o.bn_ = nullptr; }

BigInt& BigInt::operator=(BigInt&& o) {
    if (this != &o) { BN_free(bn_); bn_ = o.bn_; o.bn_ = nullptr; }
    return *this;
}

BigInt::~BigInt() { BN_free(bn_); }

char* BigInt::to_dec() const { return BN_bn2dec(bn_); }

BIGNUM* BigInt::raw() const { return bn_; }

BigInt BigInt::multiply(const BigInt& a, const BigInt& b) {
    BigInt r;
    BN_CTX* c = BN_CTX_new();
    BN_mul(r.bn_, a.bn_, b.bn_, c);
    BN_CTX_free(c);
    return r;
}

BigInt BigInt::subtract(const BigInt& a, const BigInt& b) {
    BigInt r;
    BN_sub(r.bn_, a.bn_, b.bn_);
    return r;
}

BigInt BigInt::mod_exp(const BigInt& base, const BigInt& exp, const BigInt& mod) {
    BigInt r;
    BN_CTX* c = BN_CTX_new();
    BN_mod_exp(r.bn_, base.bn_, exp.bn_, mod.bn_, c);
    BN_CTX_free(c);
    return r;
}

BigInt BigInt::mod_inverse(const BigInt& a, const BigInt& mod) {
    BigInt r;
    BN_CTX* c = BN_CTX_new();
    BN_mod_inverse(r.bn_, a.bn_, mod.bn_, c);
    BN_CTX_free(c);
    return r;
}

BigInt BigInt::mod(const BigInt& a, const BigInt& m) {
    BigInt r;
    BN_CTX* c = BN_CTX_new();
    BN_mod(r.bn_, a.bn_, m.bn_, c);
    BN_CTX_free(c);
    return r;
}

BigInt BigInt::from_bytes(const std::vector<uint8_t>& bytes) {
    BigInt r;
    BN_bin2bn(bytes.data(), bytes.size(), r.bn_);
    return r;
}

std::vector<uint8_t> BigInt::to_bytes() const {
    int sz = BN_num_bytes(bn_);
    if (sz == 0) return {0x00};
    std::vector<uint8_t> b(sz);
    BN_bn2bin(bn_, b.data());
    return b;
}

std::vector<uint8_t> BigInt::to_bytes(size_t min_size) const {
    int sz = BN_num_bytes(bn_);
    std::vector<uint8_t> b(min_size, 0x00);
    BN_bn2bin(bn_, b.data() + (min_size - sz));
    return b;
}

}
