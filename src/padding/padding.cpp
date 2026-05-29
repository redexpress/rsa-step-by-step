#include "rsa/padding.h"

#include <cstring>
#include <openssl/rand.h>

namespace rsa {

    std::vector<uint8_t> PKCS1v15::encode(const std::vector<uint8_t>& msg, int k) {
        if ((int)msg.size() > k - 11) return {};

        std::vector<uint8_t> em(k);
        em[0] = 0x00;
        em[1] = 0x02;

        int ps_len = k - msg.size() - 3;

        for (int i = 0; i < ps_len; i++) {
            uint8_t b = 0;
            do { RAND_bytes(&b, 1); } while (b == 0);
            em[2 + i] = b;
        }

        em[2 + ps_len] = 0x00;

        for (size_t i = 0; i < msg.size(); i++) {
            em[3 + ps_len + i] = msg[i];
        }

        return em;
    }

    std::vector<uint8_t> PKCS1v15::decode(const std::vector<uint8_t>& em, int k) {
        std::vector<uint8_t> em_fixed(k, 0x00);
        int copy_len = std::min((int)em.size(), k);
        std::memcpy(em_fixed.data() + (k - copy_len), em.data(), copy_len);

        if (em_fixed.size() < 11) return {};
        if (em_fixed[0] != 0x00 || em_fixed[1] != 0x02) return {};

        size_t i = 2;
        while (i < em_fixed.size() && em_fixed[i] != 0x00) i++;
        if (i >= em_fixed.size()) return {};

        std::vector<uint8_t> msg;
        for (size_t j = i + 1; j < em_fixed.size(); j++) {
            msg.push_back(em_fixed[j]);
        }

        return msg;
    }

}