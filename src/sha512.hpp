// SHA-512 autocontido (sem OpenSSL), usado para gerar o airootfs.sha512 do Arch.
// Equivale ao hashlib.sha512() usado no iso_linux.py.
// As constantes K/H foram geradas matematicamente (raiz cúbica/quadrada dos
// primeiros primos) e o resultado é conferido contra o sha512sum nos testes.
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>

namespace isob {

class Sha512 {
public:
    Sha512() { reset(); }

    void reset() {
        static const uint64_t init[8] = {
            0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
            0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
        };
        std::memcpy(h_, init, sizeof(h_));
        total_ = 0;
        buf_len_ = 0;
    }

    void update(const void* data, size_t len) {
        const uint8_t* p = static_cast<const uint8_t*>(data);
        total_ += len;
        if (buf_len_ > 0) {
            size_t take = 128 - buf_len_;
            if (take > len) take = len;
            std::memcpy(buf_ + buf_len_, p, take);
            buf_len_ += take; p += take; len -= take;
            if (buf_len_ == 128) { block(buf_); buf_len_ = 0; }
        }
        while (len >= 128) { block(p); p += 128; len -= 128; }
        if (len > 0) { std::memcpy(buf_, p, len); buf_len_ = len; }
    }

    // Finaliza e devolve o digest em hexadecimal minúsculo (128 caracteres).
    std::string hexdigest() {
        uint64_t bits_hi = total_ >> 61;          // bits altos do comprimento (128 bits)
        uint64_t bits_lo = total_ << 3;
        uint8_t pad = 0x80;
        update(&pad, 1);
        uint8_t zero = 0;
        while (buf_len_ != 112) update(&zero, 1);
        uint8_t len_bytes[16];
        for (int i = 0; i < 8; i++) len_bytes[i] = uint8_t(bits_hi >> (56 - 8 * i));
        for (int i = 0; i < 8; i++) len_bytes[8 + i] = uint8_t(bits_lo >> (56 - 8 * i));
        update(len_bytes, 16);

        static const char* hex = "0123456789abcdef";
        std::string out;
        out.reserve(128);
        for (int i = 0; i < 8; i++)
            for (int b = 7; b >= 0; b--) {
                uint8_t byte = uint8_t(h_[i] >> (8 * b));
                out.push_back(hex[byte >> 4]);
                out.push_back(hex[byte & 15]);
            }
        return out;
    }

private:
    static uint64_t rotr(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

    void block(const uint8_t* p) {
static const uint64_t K[80] = {
            0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
            0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
            0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
            0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
            0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
            0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
            0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
            0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
            0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
            0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
            0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
            0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
            0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
            0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
            0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
            0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
            0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
            0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
            0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
            0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
        };
        
        uint64_t w[80];
        for (int i = 0; i < 16; i++) {
            w[i] = 0;
            for (int b = 0; b < 8; b++) w[i] = (w[i] << 8) | p[i * 8 + b];
        }
        for (int i = 16; i < 80; i++) {
            uint64_t s0 = rotr(w[i - 15], 1) ^ rotr(w[i - 15], 8) ^ (w[i - 15] >> 7);
            uint64_t s1 = rotr(w[i - 2], 19) ^ rotr(w[i - 2], 61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint64_t a = h_[0], b = h_[1], c = h_[2], d = h_[3];
        uint64_t e = h_[4], f = h_[5], g = h_[6], h = h_[7];
        for (int i = 0; i < 80; i++) {
            uint64_t S1 = rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41);
            uint64_t ch = (e & f) ^ (~e & g);
            uint64_t t1 = h + S1 + ch + K[i] + w[i];
            uint64_t S0 = rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39);
            uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint64_t t2 = S0 + maj;
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d;
        h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += h;
    }

    uint64_t h_[8];
    uint8_t buf_[128];
    size_t buf_len_;
    uint64_t total_;
};

}  // namespace isob
