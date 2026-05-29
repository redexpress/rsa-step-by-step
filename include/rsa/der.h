#ifndef DER_H
#define DER_H

#include <cstdint>
#include <vector>

#include "rsa/rsa_key.h"

namespace rsa {

    class DER {
    public:
        // PKCS#1 RSAPublicKey
        static std::vector<uint8_t> public_key(const RSAKey& k);
        static bool decode_public_key(const std::vector<uint8_t>& der, RSAKey& k);

        // PKCS#1 RSAPrivateKey
        static std::vector<uint8_t> private_key(const RSAKey& k);
        static bool decode_private_key(const std::vector<uint8_t>& der, RSAKey& k);

        // X.509 SubjectPublicKeyInfo
        static std::vector<uint8_t> subject_public_key_info(const RSAKey& k);
        static bool decode_spki(const std::vector<uint8_t>& der, RSAKey& k);
    };

    // rsaEncryption OID: 1.2.840.113549.1.1.1
    extern const std::vector<uint32_t> OID_RSA;

}

#endif
