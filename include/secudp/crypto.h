#ifndef __SECUDP_CRYPTO_H__
#define __SECUDP_CRYPTO_H__

#include <sodium.h>
#define SECUDP_NONCEBYTES        crypto_secretbox_NONCEBYTES
#define SECUDP_MACBYTES          crypto_secretbox_MACBYTES
#define SECUDP_SESSIONKEYBYTES   crypto_kx_SESSIONKEYBYTES
#define SECUDP_KX_PUBLICBYTES    crypto_kx_PUBLICKEYBYTES
#define SECUDP_KX_PRIVATEBYTES   crypto_kx_SECRETKEYBYTES
#define SECUDP_SIGN_PUBLICBYTES  crypto_sign_PUBLICKEYBYTES
#define SECUDP_SIGN_PRIVATEBYTES crypto_sign_SECRETKEYBYTES
#define SECUDP_SIGN_BYTES        crypto_sign_BYTES

void secudp_random(void *buf, size_t len);
void secudp_sign_keypair(void *privKey, void *pubKey);
void secudp_peer_encrypt(void *ciphertext, void *mac, const void *message, size_t len, void *nonce, const void *key);
int secudp_peer_decrypt(void *message, const void *ciphertext, const void *mac, size_t len, const void *nonce, const void * key);
void secudp_host_generate_signature(void *signature, const void *message, size_t len, const void *privKey);
int secudp_host_verify_signature(const void *signature, const void *message, size_t len, const void *pubKey);
void secudp_peer_gen_key_exchange_pair(void *pubKey, void *secKey);
int secudp_peer_gen_session_keys(void *selfSendKey, void *otherSendKey, const void *selfPubKey, const void *selfSecKey, const void *otherPubKey);
int secudp_host_gen_session_keys(void *selfSendKey, void *otherSendKey, const void *selfPubKey, const void *selfSecKey, const void *otherPubKey);

#endif