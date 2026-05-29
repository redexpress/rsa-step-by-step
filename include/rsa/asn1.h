#ifndef ASN1_H
#define ASN1_H

#include <vector>

#include "rsa/bigint.h"

namespace rsa {

    class ASN1 {
    public:
        static const uint8_t TAG_INTEGER    = 0x02;
        static const uint8_t TAG_BIT_STRING = 0x03;
        static const uint8_t TAG_NULL       = 0x05;
        static const uint8_t TAG_OID        = 0x06;
        static const uint8_t TAG_SEQUENCE   = 0x30;

        // encode
        static void length(std::vector<uint8_t>& out, size_t len);
        static void integer(std::vector<uint8_t>& out, const BigInt& val);
        static void sequence(std::vector<uint8_t>& out, const std::vector<uint8_t>& body);
        static void oid(std::vector<uint8_t>& out, const std::vector<uint32_t>& arc);
        static void bit_string(std::vector<uint8_t>& out, const std::vector<uint8_t>& data);
        static void null(std::vector<uint8_t>& out);

        // decode
        static bool read_tlv(const uint8_t* d, size_t n, size_t& p,
                             uint8_t& tag, std::vector<uint8_t>& val);
        static bool read_integer(const uint8_t* d, size_t n, size_t& p, BigInt& v);
        static bool read_sequence(const uint8_t* d, size_t n, size_t& p,
                                  std::vector<uint8_t>& body);
        static bool read_oid(const uint8_t* d, size_t n, size_t& p,
                             std::vector<uint32_t>& arcs);
        static bool read_bit_string(const uint8_t* d, size_t n, size_t& p,
                                    std::vector<uint8_t>& data);
        static bool read_null(const uint8_t* d, size_t n, size_t& p);
    };

}

#endif
