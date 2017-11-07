//https://www.gnupg.org/documentation/manuals/gcrypt-devel/
//http://www.moserware.com/2009/06/first-few-milliseconds-of-https.html

#include "hex.c"
//#define GCRY_CIPHER GCRY_CIPHER_AES256
#define GCRY_CIPHER GCRY_CIPHER_AES128
#define GCRY_C_MODE GCRY_CIPHER_MODE_CBC
//#define GCRY_C_MODE GCRY_CIPHER_MODE_GCM

#define LABEL_KEY_EXPANSION "key expansion"

/*int xton(const char in)
{
    if(in >= '0' && in <= '9')
      return in - '0';
    if(in >= 'A' && in <= 'F')
      return in - 'A' + 10;
    if(in >= 'a' && in <= 'f')
      return in - 'a' + 10;

    return -1;
}

int from_hex(const char* in, char* out)
{
    size_t i;

    if(strlen(in) & 1)
        return -1;

    for (i = 0; i < strlen(in) / 2; i++)
    {
        int a = xton(in[i*2]);
        int b = xton(in[i*2 + 1]);
        if (a == -1 || b == -1)
            return -1;

        out[i] = a << 4 | b;
    }

    return out[i];
}*/

void split_premaster_secret(const char* master_secret, char* s1, char* s2)
{
    memcpy(s1, master_secret, MASTER_SECRET_SIZE/2);
   memcpy(s2, master_secret+MASTER_SECRET_SIZE/2, MASTER_SECRET_SIZE/2);
}

int p_hash(int algo, const char * secret, size_t secret_size, const char * seed, size_t seed_size, size_t result_size, char * result)
{
    int ret = -1;
    size_t algo_size = gcry_md_get_algo_dlen(algo); //unsigned int gcry_md_get_algo_dlen (int algo) [Function] Retrieve the length in bytes of the digest yielded by algorithm algo. This is often
                                                    //used prior to gcry_md_read to allocate sufficient memory for the digest.

    char * a = malloc(algo_size);
    char * b = malloc(algo_size);
    if(!a || !b)
        goto failed;

    gcry_md_hd_t hd;
    gcry_error_t e;

    e = gcry_md_open(&hd, algo, GCRY_MD_FLAG_HMAC); //Create a message digest object for algorithm algo. flags may be given as an bitwise OR of constants described below. algo may be given as 0 if the algorithms to use are later set using gcry_md_enable.
                                                    //hd is guaranteed to either receive a valid handle or NULL.

    if(e)
        goto failed;

    e = gcry_md_setkey(hd, secret, secret_size); //page 53 // release the calculated hash to pass using write method.
    if(e)
        goto failed;

    gcry_md_write(hd, seed, seed_size);//pass into the buffers //seed is buffer

    unsigned char * data = gcry_md_read(hd, algo); //gcry_md_read returns the message digest after finalizing the calculation.
    if(data)
    {
        memcpy(a, data, algo_size);
    }
    else
        goto failed_after_start;

    size_t j=0;
    while(j<result_size)
    {
        gcry_md_reset(hd);
        gcry_md_write(hd, a, algo_size);
        gcry_md_write(hd, seed, seed_size);
        unsigned char * data = gcry_md_read(hd, algo);
        if(data)
        {
            memcpy(b, data, algo_size);
        }
        else
            goto failed_after_start;

        size_t todo = algo_size;
        if(j+todo > result_size)
            todo = result_size - j;

        memcpy(result+j, b, todo);
        j += todo;

        gcry_md_reset(hd);
        gcry_md_write(hd, a, algo_size);
        data = gcry_md_read(hd, algo);
        if(data)
        {
            memcpy(a, data, algo_size);
        }
        else
            goto failed_after_start;
    }

    ret = 0;
failed_after_start:
    gcry_md_close(hd);
failed:

    if(a)
        free(a);

    if(b)
        free(b);

    return ret;
}
//TLS  Client key exchange page 329
int prf(const char* master_secret, const char* label, const char* seed, size_t seed_size, size_t result_size, char* result)
{
    // NOTE: This is TLSv1 function. Others are not supported yet.
    size_t i;
    int ret = -1;

    size_t label_and_seed_size = strlen(label) + seed_size;

    char * label_and_seed = malloc(label_and_seed_size);
    strcpy(label_and_seed, label);
    memcpy(label_and_seed+strlen(label), seed, seed_size);

    char * result2 = malloc(result_size);

    // Split premaster secret
    char s1[MASTER_SECRET_SIZE/2];
    char s2[MASTER_SECRET_SIZE/2];
    split_premaster_secret(master_secret, s1, s2);

   if(p_hash(GCRY_MD_MD5, s1, MASTER_SECRET_SIZE/2, label_and_seed, label_and_seed_size, result_size, result) == -1)
    {
        fprintf(stderr, "MD5 failed\n");
        goto failed;
    }

    if(p_hash(GCRY_MD_SHA1, s2, MASTER_SECRET_SIZE/2, label_and_seed, label_and_seed_size, result_size, result2) == -1)
    {
        fprintf(stderr, "SHA1 failed\n");
        goto failed;
    }

    for(i=0; i<result_size; i++)
        result[i] ^= result2[i];

    ret = 0;
failed:
    if(label_and_seed)
        free(label_and_seed);
    if(result2)
        free(result2);
    return ret;
}
//calculate keys page-342
//
int keys_from_master_secret(const char* master_secret, const char* client_random, const char* server_random, size_t key_len, size_t iv_len, char* client_key, char* server_key)
{
    // NOTE: only SHA diggest supported

    int ret = -1;

    size_t seed_size = CLIENT_RANDOM_SIZE + SERVER_RANDOM_SIZE;

    size_t diggest_size = 20; // SHA diggest
    size_t material_size = 2*key_len + 2*iv_len + 2*diggest_size;

    char * seed = malloc(seed_size);
    char * material = malloc(material_size);
    if(!seed || !material)
    {
        fprintf(stderr, "Memory allocation problem\n");
        goto failed;
    }
    memcpy(seed, server_random, SERVER_RANDOM_SIZE);//copying server_random value into buffer or seed
    memcpy(seed+SERVER_RANDOM_SIZE, client_random, CLIENT_RANDOM_SIZE);//copying client_random value into seed+Server_random_size

    if(prf(master_secret, LABEL_KEY_EXPANSION, seed, seed_size, material_size, material) == -1)
    {
        fprintf(stderr, "PRF failed\n");
        goto failed;
    }

    // copy data to keys
    size_t offset = 2*diggest_size; // Skip diggest
    memcpy(client_key, material+offset, key_len);
    offset += key_len;
    memcpy(server_key, material+offset, key_len);
    /*offset += key_len;
    memcpy(client_iv, material+offset, iv_len);
    offset += iv_len;
    memcpy(server_iv, material+offset, iv_len);
    offset += iv_len; */

 ret = 0;
failed:
   if(seed)
       free(seed);
    if(material)
        free(material);
   return ret;
}
//page 361

int decrypt(int from_server, const char* master_secret, const char* client_random, const char* server_random, const char* iv, const char* data, size_t data_len, char* out, size_t *out_len)
{
    // NOTE: GCRY_CIPHER_AES128 only at this point
    int ret = -1;
    size_t key_len = gcry_cipher_get_algo_keylen(GCRY_CIPHER);
    size_t iv_len = gcry_cipher_get_algo_blklen(GCRY_CIPHER);

    printf("keylen=%d, blklen=%d\n", key_len, iv_len);

    char * client_key = malloc(key_len);
    char * server_key = malloc(key_len);
    if(!client_key || !server_key)
    {
        fprintf(stderr, "Memory allocation problem\n");
        goto failed;
    }

  if(keys_from_master_secret(master_secret, client_random, server_random, key_len, iv_len, client_key, server_key) == -1)
    {
        fprintf(stderr, "Failed keys_from_master_secret\n");
        goto failed;
    }

    // Now we have keys so decrypt the data
    char * key_to_use = from_server?server_key:client_key;

    gcry_error_t     gcryError;
    gcry_cipher_hd_t gcryCipherHd;
    gcryError = gcry_cipher_open(&gcryCipherHd, GCRY_CIPHER, GCRY_C_MODE, 0);
    if(gcryError)
    {
        printf("gcry_cipher_open failed:  %s/%s\n", gcry_strsource(gcryError), gcry_strerror(gcryError));
        goto failed;
    }

    gcryError = gcry_cipher_setkey(gcryCipherHd, key_to_use, key_len);
    if (gcryError)
    {
        printf("gcry_cipher_setkey failed:  %s/%s\n", gcry_strsource(gcryError), gcry_strerror(gcryError));
        goto failed_decrypt;
    }
    printf("gcry_cipher_setkey  worked\n");

    gcryError = gcry_cipher_setiv(gcryCipherHd, iv, iv_len);
    if (gcryError)
    {
        printf("gcry_cipher_setiv failed:  %s/%s\n", gcry_strsource(gcryError), gcry_strerror(gcryError));
        goto failed_decrypt;
    }
    printf("gcry_cipher_setiv   worked\n");

    gcryError = gcry_cipher_decrypt(gcryCipherHd, out, *out_len, data, data_len);
    if (gcryError)
    {
        printf("gcry_cipher_decrypt failed:  %s/%s\n", gcry_strsource(gcryError), gcry_strerror(gcryError));
        goto failed_decrypt;
    }
    printf("gcry_cipher_decrypt worked\n");

    // Fix size
    *out_len -= out[*out_len-1] + 1; // Remove padding
    *out_len -= 20; // remove MAC

    ret = 0;
failed_decrypt:
    gcry_cipher_close(gcryCipherHd);
failed:
    if(client_key)
        free(client_key);
    if(server_key)
        free(server_key);
    return ret;
}
