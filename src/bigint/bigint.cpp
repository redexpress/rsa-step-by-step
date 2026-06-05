#include <utility>

#include "rsa/bigint.h"

namespace rsa {

    BigInt::BigInt() {
        bn_ = BN_new();
    }

    BigInt::BigInt(unsigned long value) {
        bn_ = BN_new();
        BN_set_word(bn_, value);
    }

    BigInt::BigInt(const BigInt& other) {
        bn_ = BN_dup(other.bn_);
    }

    BigInt& BigInt::operator=(const BigInt& other) {
        if (this != &other) {
            BN_free(bn_);
            bn_ = BN_dup(other.bn_);
        }

        return *this;
    }

    BigInt::BigInt(BigInt&& other) {
        bn_ = other.bn_;
        other.bn_ = nullptr;
    }

    BigInt& BigInt::operator=(BigInt&& other) {
        if (this != &other) {
            BN_free(bn_);

            bn_ = other.bn_;
            other.bn_ = nullptr;
        }

        return *this;
    }

    BigInt::~BigInt() {
        BN_free(bn_);
    }

    char* BigInt::to_dec() const {
        return BN_bn2dec(bn_);
    }

    BIGNUM* BigInt::raw() const {
        return bn_;
    }

    BigInt BigInt::multiply(
        const BigInt& a,
        const BigInt& b
    ) {
        BigInt result;

        BN_CTX* ctx = BN_CTX_new();

        BN_mul(
            result.bn_,
            a.bn_,
            b.bn_,
            ctx
        );

        BN_CTX_free(ctx);

        return result;
    }

    BigInt BigInt::subtract(
        const BigInt& a,
        const BigInt& b
    ) {
        BigInt result;

        BN_sub(
            result.bn_,
            a.bn_,
            b.bn_
        );

        return result;
    }

    BigInt BigInt::mod_exp(
        const BigInt& base,
        const BigInt& exp,
        const BigInt& mod
    ) {
        BigInt result;

        BN_CTX* ctx = BN_CTX_new();

        BN_mod_exp(
            result.bn_,
            base.bn_,
            exp.bn_,
            mod.bn_,
            ctx
        );

        BN_CTX_free(ctx);

        return result;
    }

    BigInt BigInt::mod_inverse(
        const BigInt& a,
        const BigInt& mod
    ) {
        BigInt result;

        BN_CTX* ctx = BN_CTX_new();

        BN_mod_inverse(
            result.bn_,
            a.bn_,
            mod.bn_,
            ctx
        );

        BN_CTX_free(ctx);

        return result;
    }

}