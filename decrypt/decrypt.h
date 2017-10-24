#ifndef DECRYPT_H
#define DECRYPT_H

#include <gcrypt.h>

#define CLIENT_RANDOM_SIZE  ((size_t)32)
#define SERVER_RANDOM_SIZE  ((size_t)32)
#define MASTER_SECRET_SIZE  ((size_t)48)

int xton(const char in);
int from_hex(const char* in, char* out);


void split_premaster_secret(const char* master_secret, char* s1, char* s2);
//hash calculation
int p_hash(int algo, const char * secret, size_t secret_size, const char * seed, size_t seed_size, size_t result_size, char * result);

int prf(const char* master_secret, const char* label, const char* seed, size_t seed_size, size_t result_size, char* material);
int keys_from_master_secret(const char* master_secret, const char* client_random, const char* server_random, size_t key_len, size_t iv_len, char* client_key, char* server_key);

int decrypt(int from_server, const char* master_secret, const char* client_random, const char* server_random, const char* iv, const char* data, size_t data_len, char* out, size_t * out_len);

#endif // DECRYPT_H
