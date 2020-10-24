#include "secudp/crypto.h"
 
/*
 *  Generate random bytes. This always succeeds.
 */
void secudp_random(void *buf, size_t len) 
{
  randombytes_buf(buf, len);
}

/*
 *  Generate keypair for signatures.
 */
void secudp_sign_keypair(void *pubKey, void *privKey)
{
  crypto_sign_keypair(pubKey, privKey);
}

/*
 *  Encrypt message. This always succeeds.
 */
void secudp_peer_encrypt(void *ciphertext, void *mac, const void *message, size_t len, void *nonce, const void *key) {
  secudp_random(nonce, SECUDP_NONCEBYTES);
  crypto_secretbox_detached(ciphertext, mac, message, len, nonce, key);
}

/*
 *  Decrypt message. This  returns < 0 if mac is bad and 0 otherwise.
 */
int secudp_peer_decrypt(void *message, const void *ciphertext, const void *mac, size_t len, const void *nonce, const void * key) {
  return crypto_secretbox_open_detached(message, ciphertext, mac, len, nonce, key);    
}

/*
 *  Generate signature. This always succeeds.
 */
void secudp_host_generate_signature(void *signature, const void *message, size_t len, const void *privKey) {
  crypto_sign_detached(signature, NULL, message, len, privKey);
}

/*
 *  Verify signature. This returns < 0 if signature is bad and 0 otherwise.
 */
int secudp_host_verify_signature(const void *signature, const void *message, size_t len, const void *pubKey) {
  return crypto_sign_verify_detached(signature, message, len, pubKey);
}

/*
 *  Generate public and secret key pair for exchange.
 *  This always succeeds.
 */
void secudp_peer_gen_key_exchange_pair(void *pubKey, void *secKey) {
  crypto_kx_keypair(pubKey, secKey);
}

/*
 *  Generate session keys. Use peer function in PEER_HELLO, host function in
 *  HOST_HELLO. These return < 0 if keys are bad and 0 otherwise.
 */
int secudp_peer_gen_session_keys(void *selfSendKey, void *otherSendKey, const void *selfPubKey, const void *selfSecKey, const void *otherPubKey) {
  return crypto_kx_client_session_keys(selfSendKey, otherSendKey, selfPubKey, selfSecKey, otherPubKey);
}

int secudp_host_gen_session_keys(void *selfSendKey, void *otherSendKey, const void *selfPubKey, const void *selfSecKey, const void *otherPubKey) {
  return crypto_kx_server_session_keys(selfSendKey, otherSendKey, selfPubKey, selfSecKey, otherPubKey);
}
