#include "rsa/pem.h"
#include "rsa/der.h"

#include <cstring>

namespace rsa {

    static const char B64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    static std::string base64_encode(const std::vector<uint8_t>& d) {
        std::string out;
        for (size_t i = 0; i < d.size(); i += 3) {
            uint32_t n = (uint32_t)d[i] << 16;
            bool b1 = i + 1 < d.size();
            bool b2 = i + 2 < d.size();
            if (b1) n |= (uint32_t)d[i + 1] << 8;
            if (b2) n |= (uint32_t)d[i + 2];
            out += B64[(n >> 18) & 0x3F];
            out += B64[(n >> 12) & 0x3F];
            out += b1 ? B64[(n >> 6) & 0x3F] : '=';
            out += b2 ? B64[n & 0x3F] : '=';
        }
        return out;
    }

    static bool base64_decode(const std::string& s, std::vector<uint8_t>& out) {
        int rev[128] = {};
        for (int i = 0; i < 64; ++i) rev[(int)B64[i]] = i;
        rev['='] = 0;

        if (s.size() % 4) return false;
        for (size_t i = 0; i < s.size(); i += 4) {
            uint32_t n = (uint32_t)(rev[(int)s[i]]) << 18
                       | (uint32_t)(rev[(int)s[i + 1]]) << 12
                       | (uint32_t)(rev[(int)s[i + 2]]) << 6
                       | (uint32_t)(rev[(int)s[i + 3]]);
            out.push_back((uint8_t)(n >> 16));
            if (s[i + 2] != '=') out.push_back((uint8_t)(n >> 8));
            if (s[i + 3] != '=') out.push_back((uint8_t)n);
        }
        return true;
    }

    std::string PEM::encode(const std::vector<uint8_t>& der,
                            const std::string& label) {
        std::string b64 = base64_encode(der);
        std::string out;
        out += "-----BEGIN " + label + "-----\n";
        for (size_t i = 0; i < b64.size(); i += 64)
            out += b64.substr(i, 64) + "\n";
        out += "-----END " + label + "-----\n";
        return out;
    }

    bool PEM::decode(const std::string& pem, std::string& label,
                     std::vector<uint8_t>& der) {
        auto pos = pem.find("-----BEGIN ");
        if (pos == std::string::npos) return false;
        auto end = pem.find("-----", pos + 11);
        if (end == std::string::npos) return false;
        label = pem.substr(pos + 11, end - pos - 11);

        auto data_start = pem.find("\n", end) + 1;
        auto data_end   = pem.find("-----END " + label + "-----");
        if (data_end == std::string::npos) return false;

        std::string b64;
        for (size_t i = data_start; i < data_end; ++i)
            if (pem[i] != '\n' && pem[i] != '\r') b64 += pem[i];

        return base64_decode(b64, der);
    }

    std::string PEM::public_key(const RSAKey& k) {
        return encode(DER::subject_public_key_info(k), "PUBLIC KEY");
    }

    std::string PEM::private_key(const RSAKey& k) {
        return encode(DER::private_key(k), "RSA PRIVATE KEY");
    }

    bool PEM::decode_public_key(const std::string& pem, RSAKey& k) {
        std::string label;
        std::vector<uint8_t> der;
        if (!decode(pem, label, der)) return false;
        return DER::decode_spki(der, k);
    }

    bool PEM::decode_private_key(const std::string& pem, RSAKey& k) {
        std::string label;
        std::vector<uint8_t> der;
        if (!decode(pem, label, der)) return false;
        return DER::decode_private_key(der, k);
    }

}
