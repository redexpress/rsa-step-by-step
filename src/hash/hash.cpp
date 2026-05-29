#include "rsa/hash.h"

#include <openssl/sha.h>

namespace rsa {

    std::vector<uint8_t> SHA256::digest(const std::vector<uint8_t>& data) {
        return digest(data.data(), data.size());
    }

    std::vector<uint8_t> SHA256::digest(const void* data, size_t len) {
        std::vector<uint8_t> out(DIGEST_SIZE);
        ::SHA256((const unsigned char*)data, len, out.data());
        return out;
    }

}
