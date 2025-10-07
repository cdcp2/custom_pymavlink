#pragma once
#include <stdint.h>
#include <stddef.h>
#include "mavlink_types.h"
#include "mavlink_chacha20.h"
#include "mavlink_aesctr.h"

// --- add to mavlink_cipher.h (public app-facing API) ---

#ifdef __cplusplus
extern "C" {
#endif

// Match the internal MAVLink cipher IDs you already defined
typedef enum {
    MAV_CRYPT_ALG_NONE      = MAVLINK_CIPHER_NONE,
    MAV_CRYPT_ALG_CHACHA20  = MAVLINK_CIPHER_CHACHA20,
    MAV_CRYPT_ALG_AESCTR128 = MAVLINK_CIPHER_AESCTR128,
} mav_crypt_alg_t;

/* Optional: declare the hooks your app implements/uses so we
   don't trip -Werror=missing-declarations in C++ TU's. */
bool mavlink_is_cleartext_msg(uint32_t msgid);

bool mavlink_get_crypt_config(uint8_t chan, bool is_tx, uint8_t seq,
                              mav_crypt_alg_t *alg,
                              uint8_t key_out[32],
                              uint8_t nonce_out[16],
                              uint32_t *counter0);

#ifdef __cplusplus
}
#endif

/* Derive a 32-bit counter for this packet:
   If packet has a MAVLink v2 signature, use its 48-bit timestamp LSBs.
   Otherwise fall back to the seq (8-bit) widened to 32-bit. */
static inline uint32_t mavlink_counter_from_signature(const mavlink_message_t *msg,
                                                      const mavlink_status_t *status)
{
#ifndef MAVLINK_NO_SIGN_PACKET
    (void)status;
    if ((msg->incompat_flags & 0x01u) != 0) { /* signed */
        /* signature layout: [0]=link_id, [1..6]=timestamp LE, [7..12]=sig */
        uint64_t ts = 0;
        for (int i=0;i<6;i++) ts |= ((uint64_t)msg->signature[1+i]) << (8*i);
        return (uint32_t)ts; /* LSB 32 used as counter */
    }
#endif
    return (uint32_t)msg->seq;
}

static inline uint8_t _mav_chan_from_status(const mavlink_status_t *st) {
    // fall back to 0 if signing not yet enabled
    return (st && st->signing) ? st->signing->link_id : 0;
}

static inline void mavlink_payload_encrypt(uint8_t *payload, uint8_t len,
                                           const mavlink_message_t *msg,
                                           const mavlink_status_t *st)
{
    if (!payload || !len || !msg || !st) return;
    if (mavlink_is_cleartext_msg(msg->msgid)) return;

    mav_crypt_alg_t alg;
    uint8_t key[32], nonce[16];
    uint32_t counter0 = 0;
    const uint8_t chan = _mav_chan_from_status(st);
    const uint8_t seq  = msg->seq;

    if (!mavlink_get_crypt_config(chan, /*is_tx=*/true, seq, &alg, key, nonce, &counter0)) {
        return;
    }

    if (alg == MAV_CRYPT_ALG_CHACHA20) {
        // nonce[0..11], counter0 drives the block counter
        mavlink_chacha20_xor(payload, len, key, nonce, counter0);
    } else if (alg == MAV_CRYPT_ALG_AESCTR128) {
        // nonce already encodes the counter in [12..15]
        uint8_t iv16[16];
        for (int i=0;i<16;i++) iv16[i]=nonce[i];
        aes128ctr_xor(payload, len, key /*first 16 used*/, iv16);
    }
}

static inline void mavlink_payload_decrypt(uint8_t *payload, uint8_t len,
                                           const mavlink_message_t *msg,
                                           const mavlink_status_t *st)
{
    if (!payload || !len || !msg || !st) return;

    mav_crypt_alg_t alg;
    uint8_t key[32], nonce[16];
    uint32_t counter0 = 0;
    const uint8_t chan = _mav_chan_from_status(st);
    const uint8_t seq  = msg->seq;

    if (!mavlink_get_crypt_config(chan, /*is_tx=*/false, seq, &alg, key, nonce, &counter0)) {
        return;
    }

    if (alg == MAV_CRYPT_ALG_CHACHA20) {
        mavlink_chacha20_xor(payload, len, key, nonce, counter0);
    } else if (alg == MAV_CRYPT_ALG_AESCTR128) {
        uint8_t iv16[16];
        for (int i=0;i<16;i++) iv16[i]=nonce[i];
        aes128ctr_xor(payload, len, key, iv16);
    }
}