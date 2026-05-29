#ifndef PADDING_H
#define PADDING_H

#include <vector>
#include <cstdint>

namespace rsa {

    class PKCS1v15 {
    public:
        static std::vector<uint8_t> encode(const std::vector<uint8_t>& msg, int k);
        static std::vector<uint8_t> decode(const std::vector<uint8_t>& em, int k);
    };

}

#endif