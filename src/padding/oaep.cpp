#include "rsa/oaep.h"
#include "rsa/bigint.h"
#include "rsa/hash.h"
#include "rsa/rsa_engine.h"

#include <openssl/rand.h>

#include <cstring>

namespace rsa {

    // ---------- MGF1 ----------

    [[maybe_unused]] static std::vector<uint8_t> mgf1(const uint8_t* seed,
                                                       size_t seed_len,
                                                       size_t out_len) {
        std::vector<uint8_t> out;
        for (uint32_t c = 0; out.size() < out_len; ++c) {
            std::vector<uint8_t> in(seed, seed + seed_len);
            uint8_t ctr[4] = {
                (uint8_t)(c >> 24), (uint8_t)(c >> 16),
                (uint8_t)(c >> 8),  (uint8_t)c};
            in.insert(in.end(), ctr, ctr + 4);
            std::vector<uint8_t> h = SHA256::digest(in);
            out.insert(out.end(), h.begin(), h.end());
        }
        out.resize(out_len);
        return out;
    }

    static void xor_buf(uint8_t* dst, const uint8_t* src, size_t n) {
        while (n--) *dst++ ^= *src++;
    }

    // ---------- OAEP ----------

    std::vector<uint8_t> OAEP::encode(const std::vector<uint8_t>& msg,
                                      int k,
                                      const std::vector<uint8_t>& label) {
        const int hLen = (int)SHA256::DIGEST_SIZE;

        int maxMsg = k - 2 * hLen - 2;
        if (maxMsg < 0 || (int)msg.size() > maxMsg) return {};

        // lHash = SHA256(label)
        std::vector<uint8_t> lHash = SHA256::digest(label);

        // DB = lHash || PS || 0x01 || M
        int psLen = maxMsg - (int)msg.size();
        std::vector<uint8_t> DB;
        DB.insert(DB.end(), lHash.begin(), lHash.end());
        DB.resize(DB.size() + psLen, 0x00);
        DB.push_back(0x01);
        DB.insert(DB.end(), msg.begin(), msg.end());

        // seed = random hLen bytes
        std::vector<uint8_t> seed(hLen);
        RAND_bytes(seed.data(), (int)hLen);

        // maskedDB = DB ^ MGF1(seed, k - hLen - 1)
        std::vector<uint8_t> dbMask  = mgf1(seed.data(), hLen, k - hLen - 1);
        std::vector<uint8_t> maskedDB = DB;
        xor_buf(maskedDB.data(), dbMask.data(), maskedDB.size());

        // maskedSeed = seed ^ MGF1(maskedDB, hLen)
        std::vector<uint8_t> seedMask = mgf1(maskedDB.data(), maskedDB.size(), hLen);
        std::vector<uint8_t> maskedSeed = seed;
        xor_buf(maskedSeed.data(), seedMask.data(), hLen);

        // EM = 0x00 || maskedSeed || maskedDB
        std::vector<uint8_t> EM;
        EM.push_back(0x00);
        EM.insert(EM.end(), maskedSeed.begin(), maskedSeed.end());
        EM.insert(EM.end(), maskedDB.begin(), maskedDB.end());
        return EM;
    }

    std::vector<uint8_t> OAEP::decode(const std::vector<uint8_t>& em,
                                      int k,
                                      const std::vector<uint8_t>& label) {
        const int hLen = (int)SHA256::DIGEST_SIZE;

        if ((int)em.size() != k) return {};
        if (k < 2 * hLen + 2) return {};
        if (em[0] != 0x00) return {};

        const uint8_t* maskedSeed = em.data() + 1;
        const uint8_t* maskedDB   = em.data() + 1 + hLen;
        int dbLen = k - hLen - 1;

        // seed = maskedSeed ^ MGF1(maskedDB, dbLen)
        std::vector<uint8_t> seedMask = mgf1(maskedDB, dbLen, hLen);
        std::vector<uint8_t> seed(hLen);
        for (size_t i = 0; i < hLen; ++i) seed[i] = maskedSeed[i] ^ seedMask[i];

        // DB = maskedDB ^ MGF1(seed, dbLen)
        std::vector<uint8_t> dbMask = mgf1(seed.data(), hLen, dbLen);
        std::vector<uint8_t> DB(dbLen);
        for (size_t i = 0; i < dbLen; ++i) DB[i] = maskedDB[i] ^ dbMask[i];

        // verify lHash
        std::vector<uint8_t> lHash = SHA256::digest(label);
        if (std::memcmp(DB.data(), lHash.data(), hLen) != 0) return {};

        // find 0x01 after padding
        size_t pos = hLen;
        while (pos < dbLen && DB[pos] == 0x00) ++pos;
        if (pos >= dbLen || DB[pos] != 0x01) return {};

        return std::vector<uint8_t>(DB.begin() + pos + 1, DB.end());
    }

    // ---------- high-level encrypt / decrypt ----------

    std::vector<uint8_t> OAEP::encrypt(const std::vector<uint8_t>& msg,
                                       const RSAKey& key,
                                       const std::vector<uint8_t>& label) {
        int k = key.block_size();
        std::vector<uint8_t> em = encode(msg, k, label);
        if (em.empty()) return {};

        BigInt m = BigInt::from_bytes(em);
        BigInt c = RSAEngine::encrypt(m, key);
        return c.to_bytes(k);
    }

    std::vector<uint8_t> OAEP::decrypt(const std::vector<uint8_t>& ct,
                                       const RSAKey& key,
                                       const std::vector<uint8_t>& label) {
        int k = key.block_size();

        BigInt c = BigInt::from_bytes(ct);
        BigInt m = RSAEngine::decrypt(c, key);
        return decode(m.to_bytes(k), k, label);
    }

}
