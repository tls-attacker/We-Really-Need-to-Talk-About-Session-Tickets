#include <openssl/base.h>
#include <openssl/ssl.h>
#include <vector>

const SSL_TICKET_AEAD_METHOD *ticket_init(std::vector<uint8_t> key_name,
                                          const EVP_CIPHER *cipher,
                                          std::vector<uint8_t> cipher_key,
                                          const EVP_MD *digest,
                                          std::vector<uint8_t> digest_key);
