#include "secudp/secudp.h"
#include <sodium.h>

/*
 *  Encrypt message. This always succeeds.
 */
void secudp_peer_encrypt(void *ciphertext, void *mac, const void *message, size_t len, void *nonce, const void *key) {
  randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);
  crypto_secretbox_detached(ciphertext, mac, message, len, nonce, key);
}

/*
 *  Decrypt message. This fails if MAC doesn't line up.
 */
int secudp_peer_decrypt(void *message, const void *ciphertext, const void *mac, size_t len, const void *nonce, const void * key) {
  return crypto_secretbox_open_detached(message, ciphertext, mac, len, nonce, key);    
}

void secudp_host_generate_signature(void *signature, const void *message, size_t len, const void *privKey) {
  crypto_sign_detached(signature, NULL, message, len, privKey);
}

void secudp_host_verify_signature(const void *signature, const void *message, size_t len, const void *pubKey) {
  return crypto_sign_verify_detached(signature, message, len, pubKey);
}



