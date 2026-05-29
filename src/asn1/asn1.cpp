#include "rsa/asn1.h"

#include <cstring>

namespace rsa {

    const uint8_t ASN1::TAG_INTEGER;
    const uint8_t ASN1::TAG_BIT_STRING;
    const uint8_t ASN1::TAG_NULL;
    const uint8_t ASN1::TAG_OID;
    const uint8_t ASN1::TAG_SEQUENCE;

    // ---------- encode ----------

    void ASN1::length(std::vector<uint8_t>& out, size_t len) {
        if (len < 0x80) {
            out.push_back((uint8_t)len);
            return;
        }
        uint8_t buf[8];
        int n = 0;
        for (size_t v = len; v; v >>= 8) buf[n++] = (uint8_t)(v & 0xFF);
        out.push_back((uint8_t)(0x80 | n));
        while (n--) out.push_back(buf[n]);
    }

    void ASN1::integer(std::vector<uint8_t>& out, const BigInt& val) {
        out.push_back(TAG_INTEGER);
        std::vector<uint8_t> b = val.to_bytes();
        if (b.empty() || (b[0] & 0x80)) b.insert(b.begin(), 0x00);
        length(out, b.size());
        out.insert(out.end(), b.begin(), b.end());
    }

    void ASN1::sequence(std::vector<uint8_t>& out,
                        const std::vector<uint8_t>& body) {
        out.push_back(TAG_SEQUENCE);
        length(out, body.size());
        out.insert(out.end(), body.begin(), body.end());
    }

    void ASN1::oid(std::vector<uint8_t>& out, const std::vector<uint32_t>& arc) {
        out.push_back(TAG_OID);
        std::vector<uint8_t> b;
        b.push_back((uint8_t)(arc[0] * 40 + arc[1]));
        for (size_t i = 2; i < arc.size(); ++i) {
            uint32_t v = arc[i];
            std::vector<uint8_t> tmp;
            tmp.push_back(v & 0x7F);
            for (v >>= 7; v; v >>= 7) tmp.push_back((v & 0x7F) | 0x80);
            for (auto it = tmp.rbegin(); it != tmp.rend(); ++it) b.push_back(*it);
        }
        length(out, b.size());
        out.insert(out.end(), b.begin(), b.end());
    }

    void ASN1::bit_string(std::vector<uint8_t>& out,
                          const std::vector<uint8_t>& data) {
        out.push_back(TAG_BIT_STRING);
        length(out, 1 + data.size());
        out.push_back(0x00); // unused bits
        out.insert(out.end(), data.begin(), data.end());
    }

    void ASN1::null(std::vector<uint8_t>& out) {
        out.push_back(TAG_NULL);
        out.push_back(0x00);
    }

    // ---------- decode ----------

    static bool read_len(const uint8_t* d, size_t n, size_t& p, size_t& len) {
        if (p >= n) return false;
        uint8_t b = d[p++];
        if (b < 0x80) { len = b; return true; }
        int count = b & 0x7F;
        if (p + count > n) return false;
        len = 0;
        while (count--) len = (len << 8) | d[p++];
        return true;
    }

    bool ASN1::read_tlv(const uint8_t* d, size_t n, size_t& p,
                        uint8_t& tag, std::vector<uint8_t>& val) {
        if (p >= n) return false;
        tag = d[p++];
        size_t len;
        if (!read_len(d, n, p, len)) return false;
        if (p + len > n) return false;
        val.assign(d + p, d + p + len);
        p += len;
        return true;
    }

    bool ASN1::read_integer(const uint8_t* d, size_t n, size_t& p, BigInt& v) {
        uint8_t tag;
        std::vector<uint8_t> val;
        if (!read_tlv(d, n, p, tag, val)) return false;
        if (tag != TAG_INTEGER) return false;
        v = BigInt::from_bytes(val);
        return true;
    }

    bool ASN1::read_sequence(const uint8_t* d, size_t n, size_t& p,
                             std::vector<uint8_t>& body) {
        uint8_t tag;
        if (!read_tlv(d, n, p, tag, body)) return false;
        return tag == TAG_SEQUENCE;
    }

    bool ASN1::read_oid(const uint8_t* d, size_t n, size_t& p,
                        std::vector<uint32_t>& arcs) {
        uint8_t tag;
        std::vector<uint8_t> val;
        if (!read_tlv(d, n, p, tag, val)) return false;
        if (tag != TAG_OID || val.empty()) return false;
        arcs.clear();
        arcs.push_back(val[0] / 40);
        arcs.push_back(val[0] % 40);
        size_t i = 1;
        while (i < val.size()) {
            uint32_t v = 0;
            do { v = (v << 7) | (val[i] & 0x7F); } while ((val[i++] & 0x80) && i < val.size());
            arcs.push_back(v);
        }
        return true;
    }

    bool ASN1::read_bit_string(const uint8_t* d, size_t n, size_t& p,
                               std::vector<uint8_t>& data) {
        uint8_t tag;
        std::vector<uint8_t> val;
        if (!read_tlv(d, n, p, tag, val)) return false;
        if (tag != TAG_BIT_STRING || val.size() < 2) return false;
        if (val[0] != 0x00) return false; // unused bits must be 0
        data.assign(val.begin() + 1, val.end());
        return true;
    }

    bool ASN1::read_null(const uint8_t* d, size_t n, size_t& p) {
        uint8_t tag;
        std::vector<uint8_t> val;
        if (!read_tlv(d, n, p, tag, val)) return false;
        return tag == TAG_NULL && val.empty();
    }

}
