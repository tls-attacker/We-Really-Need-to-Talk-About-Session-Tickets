#include "custom_ticket.h"
#include <assert.h>
#include <openssl/base.h>
#include <openssl/rand.h>
#include <cstring>
#include <string>


static const EVP_CIPHER *ticket_cipher = nullptr;
static const EVP_MD *ticket_digest = nullptr;
static uint8_t *ticket_key_name = nullptr;
static size_t ticket_key_name_len = 0;
static uint8_t *ticket_cipher_key = nullptr;
static size_t ticket_cipher_key_len = 0;
static uint8_t *ticket_digest_key = nullptr;
static size_t ticket_digest_key_len = 0;

static bool hmac_includes_keyname = true;

static size_t ticket_max_overhead(SSL *ssl) {
  // key name + IV + padding + hmac/digest
  return ticket_key_name_len + EVP_CIPHER_iv_length(ticket_cipher) +
         EVP_CIPHER_block_size(ticket_cipher) +
         (ticket_digest == nullptr ? 0 : EVP_MD_size(ticket_digest));
}

static bool encrypt(uint8_t *out, const uint8_t *in, size_t in_len,
                    size_t *written_counter) {
  // TODO AEAD
  // will most likely need a completely different function :/
  EVP_CIPHER_CTX *enc_ctx = EVP_CIPHER_CTX_new();
  size_t iv_len = EVP_CIPHER_iv_length(ticket_cipher);
  uint8_t *iv = (uint8_t *)OPENSSL_malloc(iv_len);

  size_t local_written = 0;

  int enc_written = 0;
  int final_enc_written = 0;

  // fprintf(stderr, "Encrypting %lu bytes (Padding %luB?)\n", in_len,
  //         (EVP_CIPHER_block_size(ticket_cipher) - in_len) %
  //             EVP_CIPHER_block_size(ticket_cipher));
  if (!iv || !enc_ctx || !RAND_bytes(iv, iv_len) ||
      !EVP_EncryptInit_ex(enc_ctx, ticket_cipher, nullptr, ticket_cipher_key,
                          iv)) {
    goto seal_error;
  }

  std::memcpy(out + local_written, iv, iv_len);
  local_written += iv_len;

  if (!EVP_EncryptUpdate(enc_ctx, out + local_written, &enc_written, in,
                         in_len) ||
      !EVP_EncryptFinal_ex(enc_ctx, out + local_written + enc_written,
                           &final_enc_written)) {
    goto seal_error;
  }
  local_written += enc_written;
  local_written += final_enc_written;

  *written_counter += local_written;

  // fprintf(stderr, "Encrypted %lu -> %luB\n", in_len, local_written);
  EVP_CIPHER_CTX_cleanup(enc_ctx);
  OPENSSL_free(enc_ctx);
  OPENSSL_free(iv);
  return true;
seal_error:
  EVP_CIPHER_CTX_cleanup(enc_ctx);
  OPENSSL_free(enc_ctx);
  OPENSSL_free(iv);
  return false;
}

static bool decrypt(uint8_t *out, size_t max_out_len, size_t *out_len,
                    const uint8_t *in, size_t in_len) {
  EVP_CIPHER_CTX *dec_ctx = EVP_CIPHER_CTX_new();
  size_t iv_len = EVP_CIPHER_iv_length(ticket_cipher);

  int written = 0;
  if (in_len < iv_len ||
      !EVP_DecryptInit_ex(dec_ctx, ticket_cipher, nullptr, ticket_cipher_key,
                          in) ||
      !EVP_DecryptUpdate(dec_ctx, out, &written, in + iv_len,
                         in_len - iv_len)) {
    goto open_error;
  }
  *out_len += written;

  if (!EVP_DecryptFinal_ex(dec_ctx, out + written, &written)) {
    goto open_error;
  }
  *out_len += written;

  // fprintf(stderr, "Decrypted %luB -> %luB\n", in_len, *out_len);
  EVP_CIPHER_CTX_cleanup(dec_ctx);
  OPENSSL_free(dec_ctx);
  return true;
open_error:
  EVP_CIPHER_CTX_cleanup(dec_ctx);
  OPENSSL_free(dec_ctx);
  return false;
}

static bool hmac(uint8_t *out, const uint8_t *in, size_t in_len,
                 size_t *written_counter) {
  if (ticket_digest == NULL) {
    return true;
  }

  unsigned int hmac_written;
  if (!HMAC(ticket_digest, ticket_digest_key, ticket_cipher_key_len, in, in_len,
            out, &hmac_written)) {
    return false;
  }
  if (written_counter != nullptr) {
    *written_counter += hmac_written;
  }
  return true;
}

static int ticket_seal(SSL *ssl, uint8_t *out, size_t *out_len,
                       size_t max_out_len, const uint8_t *in, size_t in_len) {
  size_t written = 0;
  // fprintf(stderr, "Sealing ticket %luB\n", in_len);

  // write key name
  std::memcpy(out + written, ticket_key_name, ticket_key_name_len);
  written += ticket_key_name_len;

  if (!encrypt(out + written, in, in_len, &written) ||
      !hmac(out + written,
            out + (hmac_includes_keyname ? 0 : ticket_key_name_len),
            written - (hmac_includes_keyname ? 0 : ticket_key_name_len),
            &written)) {
    return 0;
  }
  *out_len = written;
  fprintf(stderr, "Sealed ticket %luB -> %luB\n", in_len, *out_len);
  return 1;
}

static ssl_ticket_aead_result_t ticket_open(SSL *ssl, uint8_t *out,
                                            size_t *out_len, size_t max_out_len,
                                            const uint8_t *in, size_t in_len) {
  // fprintf(stderr, "Opening ticket %luB\n", in_len);
  if (in_len < ticket_key_name_len ||
      CRYPTO_memcmp(ticket_key_name, in, ticket_key_name_len)) {
    fprintf(stderr, "Failed to verify keyname\n");
    return ssl_ticket_aead_ignore_ticket;
  }
  size_t hmac_len = 0;
  if (ticket_digest != NULL) {
    hmac_len = EVP_MD_size(ticket_digest);
    uint8_t *correct_hmac = (uint8_t *)OPENSSL_malloc(hmac_len);
    hmac(correct_hmac, in + (hmac_includes_keyname ? 0 : ticket_key_name_len),
         in_len - hmac_len - (hmac_includes_keyname ? 0 : ticket_key_name_len),
         nullptr);

    if (in_len < (ticket_key_name_len + hmac_len) ||
        CRYPTO_memcmp(correct_hmac, in + (in_len - hmac_len), hmac_len) != 0) {
      OPENSSL_free(correct_hmac);
      fprintf(stderr, "Failed to verify hmac\n");
      return ssl_ticket_aead_ignore_ticket;
    }
    OPENSSL_free(correct_hmac);
  }
  // decrypt
  *out_len = 0;
  if (!decrypt(out, max_out_len, out_len, in + ticket_key_name_len,
               in_len - ticket_key_name_len - hmac_len)) {
    fprintf(stderr, "Failed to decrypt\n");
    // allows for padding oracle on CBC suites
    return ssl_ticket_aead_error;
  }
  fprintf(stderr, "Opened ticket %luB -> %luB\n", in_len, *out_len);
  return ssl_ticket_aead_success;
}

static const SSL_TICKET_AEAD_METHOD rsTicketMethod = {
    ticket_max_overhead,
    ticket_seal,
    ticket_open,
};

static uint8_t *vectorToBuf(std::vector<uint8_t> vector) {
  uint8_t *buf = (uint8_t *)OPENSSL_malloc(vector.size());
  memcpy(buf, vector.data(), vector.size());
  return buf;
}

const SSL_TICKET_AEAD_METHOD *ticket_init(std::vector<uint8_t> key_name,
                                          const EVP_CIPHER *cipher,
                                          std::vector<uint8_t> cipher_key,
                                          const EVP_MD *digest,
                                          std::vector<uint8_t> digest_key) {
  if (ticket_cipher != nullptr || ticket_digest != nullptr ||
      ticket_key_name != nullptr || ticket_cipher_key != nullptr ||
      ticket_digest_key != nullptr) {
    return nullptr;
  }
  ticket_cipher = cipher;
  ticket_digest = digest;
  ticket_key_name = vectorToBuf(key_name);
  ticket_key_name_len = key_name.size();
  ticket_cipher_key = vectorToBuf(cipher_key);
  ticket_cipher_key_len = cipher_key.size();
  ticket_digest_key = vectorToBuf(digest_key);
  ticket_digest_key_len = digest_key.size();
  return &rsTicketMethod;
}
