#ifndef PEM_H
#define PEM_H

#include <cstdint>
#include <string>
#include <vector>

#include "rsa/rsa_key.h"

namespace rsa {

    class PEM {
    public:
        // raw DER ↔ PEM armor
        static std::string encode(const std::vector<uint8_t>& der,
                                  const std::string& label);
        static bool decode(const std::string& pem, std::string& label,
                           std::vector<uint8_t>& der);

        // convenience: key ↔ PEM
        static std::string public_key(const RSAKey& k);
        static std::string private_key(const RSAKey& k);
        static bool decode_public_key(const std::string& pem, RSAKey& k);
        static bool decode_private_key(const std::string& pem, RSAKey& k);
    };

}

#endif
