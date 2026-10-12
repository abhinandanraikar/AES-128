/*
 * aes_ref_model.c
 * ---------------
 * DPI-C golden reference model for AES-128 encryption.
 *
 * This file is a stub. Replace the body of c_ref_model_encrypt() with
 * a known-good AES-128 implementation. Two recommended options:
 *
 * Option 1 — OpenSSL (simplest, widely available):
 *   #include <openssl/aes.h>
 *   void c_ref_model_encrypt(const svBitVecVal *msg, const svBitVecVal *key,
 *                             svBitVecVal *ciphertext) {
 *       AES_KEY aes_key;
 *       AES_set_encrypt_key((unsigned char*)key, 128, &aes_key);
 *       AES_encrypt((unsigned char*)msg, (unsigned char*)ciphertext, &aes_key);
 *   }
 *   Compile with: xrun ... -I$(OPENSSL_DIR)/include -L$(OPENSSL_DIR)/lib -lssl -lcrypto
 *
 * Option 2 — Tiny-AES-c (public domain, no dependencies, drop-in):
 *   https://github.com/kokke/tiny-AES-c
 *   Copy aes.c and aes.h into sim/, then call AES128_ECB_encrypt().
 *
 * The function signature must match the DPI-C import in tb_aes128_uvm.sv:
 *   import "DPI-C" context function void c_ref_model_encrypt(
 *       input  bit [127:0] msg,
 *       input  bit [127:0] key,
 *       output bit [127:0] ciphertext
 *   );
 */

#include "svdpi.h"
#include <string.h>
#include <stdio.h>

void c_ref_model_encrypt(
    const svBitVecVal *msg,
    const svBitVecVal *key,
    svBitVecVal       *ciphertext)
{
    /*
     * TODO: Replace this stub with a real AES-128 ECB encryption call.
     * The stub currently copies msg to ciphertext (identity transform)
     * which will cause all scoreboard comparisons to fail -- this is
     * intentional so you notice immediately if the stub is not replaced.
     */
    fprintf(stderr, "[REF MODEL] WARNING: using stub -- replace with real AES-128 implementation\n");
    memcpy(ciphertext, msg, 16); /* 128 bits = 16 bytes */
}