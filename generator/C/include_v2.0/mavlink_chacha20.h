#pragma once
#include <stdint.h>
#include <stddef.h>

/* RFC 8439 ChaCha20 - minimal stream XOR. Nonce=12 bytes, counter=32-bit. */
static inline uint32_t __rotl32(uint32_t x, int r){ return (x<<r) | (x>>(32-r)); }
#define QR(a,b,c,d) do{ \
  a += b; d ^= a; d = __rotl32(d,16); \
  c += d; b ^= c; b = __rotl32(b,12); \
  a += b; d ^= a; d = __rotl32(d, 8); \
  c += d; b ^= c; b = __rotl32(b, 7); \
}while(0)

static inline void chacha20_block(uint32_t out[16], const uint32_t in[16]){
    uint32_t x[16];
    for (int i=0;i<16;i++) x[i]=in[i];
    for (int r=0;r<10;r++) {
        /* column rounds */
        QR(x[0],x[4],x[8],x[12]);  QR(x[1],x[5],x[9],x[13]);
        QR(x[2],x[6],x[10],x[14]); QR(x[3],x[7],x[11],x[15]);
        /* diagonal rounds */
        QR(x[0],x[5],x[10],x[15]); QR(x[1],x[6],x[11],x[12]);
        QR(x[2],x[7],x[8],x[13]);  QR(x[3],x[4],x[9],x[14]);
    }
    for (int i=0;i<16;i++) out[i]=x[i]+in[i];
}

static inline void mavlink_chacha20_xor(uint8_t *buf, size_t len,
                                        const uint8_t key[32],
                                        const uint8_t nonce12[12],
                                        uint32_t counter)
{
    /* constants */
    static const uint32_t cst[4] = {0x61707865u,0x3320646eu,0x79622d32u,0x6b206574u};
    uint32_t state[16];
    state[0]=cst[0]; state[1]=cst[1]; state[2]=cst[2]; state[3]=cst[3];
    /* key in little endian */
    for (int i=0;i<8;i++){
        state[4+i] = (uint32_t)key[i*4] | ((uint32_t)key[i*4+1]<<8) |
                     ((uint32_t)key[i*4+2]<<16) | ((uint32_t)key[i*4+3]<<24);
    }
    state[12]=counter;
    /* nonce 96-bit little-endian */
    for (int i=0;i<3;i++){
        state[13+i] = (uint32_t)nonce12[i*4] | ((uint32_t)nonce12[i*4+1]<<8) |
                      ((uint32_t)nonce12[i*4+2]<<16) | ((uint32_t)nonce12[i*4+3]<<24);
    }

    uint8_t ks[64];
    uint32_t out[16];
    size_t off=0;
    while (off<len){
        chacha20_block(out, state);
        for (int i=0;i<16;i++){
            ks[i*4+0]=(uint8_t)(out[i] & 0xFF);
            ks[i*4+1]=(uint8_t)((out[i]>>8) & 0xFF);
            ks[i*4+2]=(uint8_t)((out[i]>>16)& 0xFF);
            ks[i*4+3]=(uint8_t)((out[i]>>24)& 0xFF);
        }
        size_t n = (len-off > 64) ? 64 : (len-off);
        for (size_t i=0;i<n;i++) buf[off+i] ^= ks[i];
        off += n;
        state[12]++; /* next block counter */
    }
}
