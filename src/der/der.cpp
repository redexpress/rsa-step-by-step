#include <openssl/bn.h>

#include "rsa/der.h"
#include "rsa/asn1.h"

namespace rsa {

    const std::vector<uint32_t> OID_RSA = {1, 2, 840, 113549, 1, 1, 1};

    std::vector<uint8_t> DER::public_key(const RSAKey& k) {
        std::vector<uint8_t> body;
        ASN1::integer(body, k.n);
        ASN1::integer(body, k.e);
        std::vector<uint8_t> out;
        ASN1::sequence(out, body);
        return out;
    }

    std::vector<uint8_t> DER::private_key(const RSAKey& k) {
        std::vector<uint8_t> body;
        ASN1::integer(body, BigInt(0));   // version
        ASN1::integer(body, k.n);
        ASN1::integer(body, k.e);
        ASN1::integer(body, k.d);
        ASN1::integer(body, k.p);
        ASN1::integer(body, k.q);
        ASN1::integer(body, k.dp);
        ASN1::integer(body, k.dq);
        ASN1::integer(body, k.qinv);
        std::vector<uint8_t> out;
        ASN1::sequence(out, body);
        return out;
    }

    std::vector<uint8_t> DER::subject_public_key_info(const RSAKey& k) {
        std::vector<uint8_t> alg_body;
        ASN1::oid(alg_body, OID_RSA);
        ASN1::null(alg_body);
        std::vector<uint8_t> alg;
        ASN1::sequence(alg, alg_body);

        std::vector<uint8_t> pk_der = public_key(k);
        std::vector<uint8_t> bits;
        ASN1::bit_string(bits, pk_der);

        std::vector<uint8_t> body;
        body.insert(body.end(), alg.begin(), alg.end());
        body.insert(body.end(), bits.begin(), bits.end());

        std::vector<uint8_t> out;
        ASN1::sequence(out, body);
        return out;
    }

    bool DER::decode_public_key(const std::vector<uint8_t>& der, RSAKey& k) {
        size_t p = 0;
        std::vector<uint8_t> body;
        if (!ASN1::read_sequence(der.data(), der.size(), p, body)) return false;
        size_t q = 0;
        if (!ASN1::read_integer(body.data(), body.size(), q, k.n)) return false;
        if (!ASN1::read_integer(body.data(), body.size(), q, k.e)) return false;
        if (q != body.size()) return false;
        k.set_block_size(BN_num_bytes(k.n.raw()));
        return true;
    }

    bool DER::decode_private_key(const std::vector<uint8_t>& der, RSAKey& k) {
        size_t p = 0;
        std::vector<uint8_t> body;
        if (!ASN1::read_sequence(der.data(), der.size(), p, body)) return false;
        size_t q = 0;
        BigInt ver;
        if (!ASN1::read_integer(body.data(), body.size(), q, ver)) return false;
        if (!ASN1::read_integer(body.data(), body.size(), q, k.n)) return false;
        if (!ASN1::read_integer(body.data(), body.size(), q, k.e)) return false;
        if (!ASN1::read_integer(body.data(), body.size(), q, k.d)) return false;
        if (!ASN1::read_integer(body.data(), body.size(), q, k.p)) return false;
        if (!ASN1::read_integer(body.data(), body.size(), q, k.q)) return false;
        if (!ASN1::read_integer(body.data(), body.size(), q, k.dp)) return false;
        if (!ASN1::read_integer(body.data(), body.size(), q, k.dq)) return false;
        if (!ASN1::read_integer(body.data(), body.size(), q, k.qinv)) return false;
        if (q != body.size()) return false;
        k.set_block_size(BN_num_bytes(k.n.raw()));
        return true;
    }

    bool DER::decode_spki(const std::vector<uint8_t>& der, RSAKey& k) {
        size_t p = 0;
        std::vector<uint8_t> body;
        if (!ASN1::read_sequence(der.data(), der.size(), p, body)) return false;
        size_t q = 0;

        // AlgorithmIdentifier
        std::vector<uint8_t> alg_body;
        if (!ASN1::read_sequence(body.data(), body.size(), q, alg_body)) return false;
        size_t r = 0;
        std::vector<uint32_t> arcs;
        if (!ASN1::read_oid(alg_body.data(), alg_body.size(), r, arcs)) return false;
        if (arcs != OID_RSA) return false;
        if (!ASN1::read_null(alg_body.data(), alg_body.size(), r)) return false;

        // BIT STRING wrapping RSAPublicKey
        std::vector<uint8_t> pk_der;
        if (!ASN1::read_bit_string(body.data(), body.size(), q, pk_der)) return false;
        if (!decode_public_key(pk_der, k)) return false;
        if (q != body.size()) return false;
        return true;
    }

}
