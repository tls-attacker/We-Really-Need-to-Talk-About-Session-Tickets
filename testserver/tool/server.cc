/* Copyright (c) 2014, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

#include <openssl/base.h>

#include <memory>

#include <openssl/err.h>
#include <openssl/hpke.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "internal.h"
#include "transport_common.h"

#include <stdexcept>
#include "ticketstuff/custom_ticket.h"


static const struct argument kArguments[] = {
    {
        "-accept",
        kRequiredArgument,
        "The port of the server to bind on; eg 45102",
    },
    {
        "-cipher",
        kOptionalArgument,
        "An OpenSSL-style cipher suite string that configures the offered "
        "ciphers",
    },
    {
        "-curves",
        kOptionalArgument,
        "An OpenSSL-style ECDH curves list that configures the offered curves",
    },
    {
        "-max-version",
        kOptionalArgument,
        "The maximum acceptable protocol version",
    },
    {
        "-min-version",
        kOptionalArgument,
        "The minimum acceptable protocol version",
    },
    {
        "-key",
        kOptionalArgument,
        "PEM-encoded file containing the private key. A self-signed "
        "certificate is generated at runtime if this argument is not provided.",
    },
    {
        "-cert",
        kOptionalArgument,
        "PEM-encoded file containing the leaf certificate and optional "
        "certificate chain. This is taken from the -key argument if this "
        "argument is not provided.",
    },
    {
        "-ocsp-response",
        kOptionalArgument,
        "OCSP response file to send",
    },
    {
        "-ech-key",
        kOptionalArgument,
        "File containing the private key corresponding to the ECHConfig.",
    },
    {
        "-ech-config",
        kOptionalArgument,
        "File containing one ECHConfig.",
    },
    {
        "-loop",
        kBooleanArgument,
        "The server will continue accepting new sequential connections.",
    },
    {
        "-early-data",
        kBooleanArgument,
        "Allow early data",
    },
    {
        "-www",
        kBooleanArgument,
        "The server will print connection information in response to a "
        "HTTP GET request.",
    },
    {
        "-debug",
        kBooleanArgument,
        "Print debug information about the handshake",
    },
    {
        "-require-any-client-cert",
        kBooleanArgument,
        "The server will require a client certificate.",
    },
    {
        "-jdk11-workaround",
        kBooleanArgument,
        "Enable the JDK 11 workaround",
    },
    // ticket stuff
    {
        "-ticketKeyName",
        kOptionalArgument,
        "Use this key name (hex; defaults to random)",
    },
    {
        "-ticketKeyNameLen",
        kOptionalArgument,
        "To which length the ticketKeyName should be expanded (defaults to "
        "None/16)",
    },
    {
        "-ticketEnc",
        kOptionalArgument,
        "Which encryption algo to use for tickets (defaults to AES-128-CBC)",
    },
    {
        "-ticketEncKey",
        kOptionalArgument,
        "Use specific STEK (hex; defaults to random)",
    },
    {
        "-ticketHMac",
        kOptionalArgument,
        "Which HMAC algo to use for tickets (defaults to SHA256)",
    },
    {
        "-ticketHMacKey",
        kOptionalArgument,
        "Use specific HMAC Key (hex; defaults to random)",
    },
    {
        "-ticketHMacKeyLen",
        kOptionalArgument,
        "To which length the ticketHMacKey should be expanded (defaults to "
        "None/16)",
    },
    {
        "",
        kOptionalArgument,
        "",
    },
};

static bool LoadOCSPResponse(SSL_CTX *ctx, const char *filename) {
  ScopedFILE f(fopen(filename, "rb"));
  std::vector<uint8_t> data;
  if (f == nullptr ||
      !ReadAll(&data, f.get())) {
    fprintf(stderr, "Error reading %s.\n", filename);
    return false;
  }

  if (!SSL_CTX_set_ocsp_response(ctx, data.data(), data.size())) {
    return false;
  }

  return true;
}

static bssl::UniquePtr<EVP_PKEY> MakeKeyPairForSelfSignedCert() {
  bssl::UniquePtr<EC_KEY> ec_key(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
  if (!ec_key || !EC_KEY_generate_key(ec_key.get())) {
    fprintf(stderr, "Failed to generate key pair.\n");
    return nullptr;
  }
  bssl::UniquePtr<EVP_PKEY> evp_pkey(EVP_PKEY_new());
  if (!evp_pkey || !EVP_PKEY_assign_EC_KEY(evp_pkey.get(), ec_key.release())) {
    fprintf(stderr, "Failed to assign key pair.\n");
    return nullptr;
  }
  return evp_pkey;
}

static bssl::UniquePtr<X509> MakeSelfSignedCert(EVP_PKEY *evp_pkey,
                                                const int valid_days) {
  bssl::UniquePtr<X509> x509(X509_new());
  uint32_t serial;
  RAND_bytes(reinterpret_cast<uint8_t*>(&serial), sizeof(serial));
  ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), serial >> 1);
  X509_gmtime_adj(X509_get_notBefore(x509.get()), 0);
  X509_gmtime_adj(X509_get_notAfter(x509.get()), 60 * 60 * 24 * valid_days);

  X509_NAME* subject = X509_get_subject_name(x509.get());
  X509_NAME_add_entry_by_txt(subject, "C", MBSTRING_ASC,
                             reinterpret_cast<const uint8_t *>("US"), -1, -1,
                             0);
  X509_NAME_add_entry_by_txt(subject, "O", MBSTRING_ASC,
                             reinterpret_cast<const uint8_t *>("BoringSSL"), -1,
                             -1, 0);
  X509_set_issuer_name(x509.get(), subject);

  if (!X509_set_pubkey(x509.get(), evp_pkey)) {
    fprintf(stderr, "Failed to set public key.\n");
    return nullptr;
  }
  if (!X509_sign(x509.get(), evp_pkey, EVP_sha256())) {
    fprintf(stderr, "Failed to sign certificate.\n");
    return nullptr;
  }
  return x509;
}

static void InfoCallback(const SSL *ssl, int type, int value) {
  switch (type) {
    case SSL_CB_HANDSHAKE_START:
      fprintf(stderr, "Handshake started.\n");
      break;
    case SSL_CB_HANDSHAKE_DONE:
      fprintf(stderr, "Handshake done.\n");
      break;
    case SSL_CB_ACCEPT_LOOP:
      fprintf(stderr, "Handshake progress: %s\n", SSL_state_string_long(ssl));
      break;
  }
}

static FILE *g_keylog_file = nullptr;

static void KeyLogCallback(const SSL *ssl, const char *line) {
  fprintf(g_keylog_file, "%s\n", line);
  fflush(g_keylog_file);
}

static bool HandleWWW(SSL *ssl) {
  bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
  if (!bio) {
    fprintf(stderr, "Cannot create BIO for response\n");
    return false;
  }

  BIO_puts(bio.get(), "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n");
  PrintConnectionInfo(bio.get(), ssl);

  char request[4];
  size_t request_len = 0;
  while (request_len < sizeof(request)) {
    int ssl_ret =
        SSL_read(ssl, request + request_len, sizeof(request) - request_len);
    if (ssl_ret <= 0) {
      int ssl_err = SSL_get_error(ssl, ssl_ret);
      PrintSSLError(stderr, "Error while reading", ssl_err, ssl_ret);
      return false;
    }
    request_len += static_cast<size_t>(ssl_ret);
  }

  // Assume simple HTTP request, print status.
  if (memcmp(request, "GET ", 4) == 0) {
    const uint8_t *response;
    size_t response_len;
    if (BIO_mem_contents(bio.get(), &response, &response_len)) {
      SSL_write(ssl, response, response_len);
    }
  }
  return true;
}

static std::vector<uint8_t> parse_hex(std::string hex_string) {
  std::vector<uint8_t> ret;
  if (hex_string.length() % 2 != 0) {
    return ret;
  }
  for (long unsigned int i = 0; i < hex_string.length() / 2; i++) {
    uint8_t byte = 0;
    for (int j = 0; j < 2; j++) {
      char c = hex_string[(i * 2) + j];
      uint8_t half_byte;
      if (c >= '0' && c <= '9') {
        half_byte = c - '0';
      } else if (c >= 'a' && c <= 'f') {
        half_byte = c - 'a' + 10;
      } else if (c >= 'A' && c <= 'F') {
        half_byte = c - 'A' + 10;
      } else {
        half_byte = 0;
      }
      byte = (byte << 4) | half_byte;
    }
    ret.push_back(byte);
  }
  return ret;
}

static std::vector<uint8_t> expandTruncate(std::vector<uint8_t> toexpand,
                                           std::size_t target_size) {
  std::vector<uint8_t> ret(toexpand);
  int i = 0;
  while (ret.size() < target_size) {
    ret.push_back(ret.at(i));
  }
  while (ret.size() > target_size) {
    ret.pop_back();
  }
  return ret;
}

static std::vector<uint8_t> randVector(size_t size) {
  std::vector<uint8_t> ret;
  uint8_t *buf = (uint8_t *)OPENSSL_malloc(size);
  RAND_bytes(buf, size);
  for (size_t i = 0; i < size; i++) {
    ret.push_back(buf[i]);
  }
  OPENSSL_free(buf);
  return ret;
}

static std::string getStringArg(std::map<std::string, std::string> args_map,
                                std::string arg_name, std::string default_val) {
  if (args_map.count(arg_name) != 0) {
    return args_map[arg_name];
  }
  return default_val;
}

static unsigned long parseUnsignedLongArg(
    std::map<std::string, std::string> args_map, std::string arg_name,
    unsigned long default_val) {
  if (args_map.count(arg_name) != 0) {
    unsigned long ret = std::stoul(args_map[arg_name]);
    return ret;
  }
  return default_val;
}

static std::vector<uint8_t> parseHexArg(
    std::map<std::string, std::string> args_map, std::string arg_name,
    bool doExpandTruncate, size_t target_length) {
  if (args_map.count(arg_name) != 0) {
    std::string arg = args_map[arg_name];
    std::vector<uint8_t> ret = parse_hex(arg);
    if (ret.size() == 0) {
      fprintf(stderr, "Failed to parse %s - an empty vector will be used\n",
              arg_name.c_str());
      return ret;
    }
    if (doExpandTruncate) {
      fprintf(stderr, "%s size %lu -> %lu\n", arg_name.c_str(), ret.size(),
              target_length);
      ret = expandTruncate(ret, target_length);
    }
    return ret;
  } else {
    fprintf(stderr, "Generating random %s of size %lu\n", arg_name.c_str(),
            target_length);
    return randVector(target_length);
  }
}

bool Server(const std::vector<std::string> &args) {
  if (!InitSocketLibrary()) {
    return false;
  }

  std::map<std::string, std::string> args_map;

  if (!ParseKeyValueArguments(&args_map, args, kArguments)) {
    PrintUsage(kArguments);
    return false;
  }

  bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));

  {
    // Ticket Stuff
    // parse lengths and algos
    // key name
    size_t keyNameLen = parseUnsignedLongArg(args_map, "-ticketKeyNameLen", 16);


    // enc
    std::string encAlgoName =
        getStringArg(args_map, "-ticketEnc", "AES-128-CBC");
    const EVP_CIPHER *encAlgo = EVP_get_cipherbyname(encAlgoName.c_str());

    if (OPENSSL_strcasecmp(encAlgoName.c_str(), "none") == 0 ||
        OPENSSL_strcasecmp(encAlgoName.c_str(), "null") == 0) {
      encAlgo = EVP_enc_null();
    }
    if (encAlgo == NULL) {
      fprintf(stderr, "Failed to parse cipher.\n");
      return false;
    }
    size_t encKeyLen = EVP_CIPHER_key_length(encAlgo);

    // mac
    size_t macKeyLen = parseUnsignedLongArg(args_map, "-ticketHMacKeyLen", 16);
    std::string macAlgoName = getStringArg(args_map, "-ticketHMac", "SHA256");
    const EVP_MD *macAlgo = EVP_get_digestbyname(macAlgoName.c_str());

    if (OPENSSL_strcasecmp(macAlgoName.c_str(), "none") == 0 ||
        OPENSSL_strcasecmp(macAlgoName.c_str(), "null") == 0) {
      macAlgo = NULL;
      macKeyLen = 0;
    } else if (macAlgo == NULL) {
      fprintf(stderr, "Failed to parse mac algo.\n");
      return false;
    }

    // parse actual keys
    std::vector<uint8_t> keyName =
        parseHexArg(args_map, "-ticketKeyName",
                    args_map.count("-ticketKeyNameLen") != 0, keyNameLen);
    std::vector<uint8_t> macKey =
        parseHexArg(args_map, "-ticketHMacKey",
                    args_map.count("-ticketHMacKeyLen") != 0, macKeyLen);

    std::vector<uint8_t> encKey =
        parseHexArg(args_map, "-ticketEncKey", true, encKeyLen);

    if (encKey.size() != encKeyLen) {
      fprintf(
          stderr,
          "ticketEncKey must have appropriate length (Expected: %lu, got %lu",
          encKey.size(), encKeyLen);
      return false;
    }

    auto aead_method = ticket_init(keyName, encAlgo, encKey, macAlgo, macKey);
    if (!aead_method) {
      fprintf(stderr, "Failed to initialize ticket.\n");
      return false;
    }
    SSL_CTX_set_ticket_aead_method(ctx.get(), aead_method);
  }

  const char *keylog_file = getenv("SSLKEYLOGFILE");
  if (keylog_file) {
    g_keylog_file = fopen(keylog_file, "a");
    if (g_keylog_file == nullptr) {
      perror("fopen");
      return false;
    }
    SSL_CTX_set_keylog_callback(ctx.get(), KeyLogCallback);
  }

  // Server authentication is required.
  if (args_map.count("-key") != 0) {
    std::string key = args_map["-key"];
    if (!SSL_CTX_use_PrivateKey_file(ctx.get(), key.c_str(),
                                     SSL_FILETYPE_PEM)) {
      fprintf(stderr, "Failed to load private key: %s\n", key.c_str());
      return false;
    }
    const std::string &cert =
        args_map.count("-cert") != 0 ? args_map["-cert"] : key;
    if (!SSL_CTX_use_certificate_chain_file(ctx.get(), cert.c_str())) {
      fprintf(stderr, "Failed to load cert chain: %s\n", cert.c_str());
      return false;
    }
  } else {
    bssl::UniquePtr<EVP_PKEY> evp_pkey = MakeKeyPairForSelfSignedCert();
    if (!evp_pkey) {
      return false;
    }
    bssl::UniquePtr<X509> cert =
        MakeSelfSignedCert(evp_pkey.get(), 365 /* valid_days */);
    if (!cert) {
      return false;
    }
    if (!SSL_CTX_use_PrivateKey(ctx.get(), evp_pkey.get())) {
      fprintf(stderr, "Failed to set private key.\n");
      return false;
    }
    if (!SSL_CTX_use_certificate(ctx.get(), cert.get())) {
      fprintf(stderr, "Failed to set certificate.\n");
      return false;
    }
  }

  if (args_map.count("-ech-key") + args_map.count("-ech-config") == 1) {
    fprintf(stderr, "-ech-config and -ech-key must be specified together.\n");
    return false;
  }

  if (args_map.count("-ech-key") != 0) {
    // Load the ECH private key.
    std::string ech_key_path = args_map["-ech-key"];
    ScopedFILE ech_key_file(fopen(ech_key_path.c_str(), "rb"));
    std::vector<uint8_t> ech_key;
    if (ech_key_file == nullptr || !ReadAll(&ech_key, ech_key_file.get())) {
      fprintf(stderr, "Error reading %s\n", ech_key_path.c_str());
      return false;
    }

    // Load the ECHConfig.
    std::string ech_config_path = args_map["-ech-config"];
    ScopedFILE ech_config_file(fopen(ech_config_path.c_str(), "rb"));
    std::vector<uint8_t> ech_config;
    if (ech_config_file == nullptr ||
        !ReadAll(&ech_config, ech_config_file.get())) {
      fprintf(stderr, "Error reading %s\n", ech_config_path.c_str());
      return false;
    }

    bssl::UniquePtr<SSL_ECH_KEYS> keys(SSL_ECH_KEYS_new());
    bssl::ScopedEVP_HPKE_KEY key;
    if (!keys ||
        !EVP_HPKE_KEY_init(key.get(), EVP_hpke_x25519_hkdf_sha256(),
                           ech_key.data(), ech_key.size()) ||
        !SSL_ECH_KEYS_add(keys.get(),
                          /*is_retry_config=*/1, ech_config.data(),
                          ech_config.size(), key.get()) ||
        !SSL_CTX_set1_ech_keys(ctx.get(), keys.get())) {
      fprintf(stderr, "Error setting server's ECHConfig and private key\n");
      return false;
    }
  }

  if (args_map.count("-cipher") != 0 &&
      !SSL_CTX_set_strict_cipher_list(ctx.get(), args_map["-cipher"].c_str())) {
    fprintf(stderr, "Failed setting cipher list\n");
    return false;
  }

  if (args_map.count("-curves") != 0 &&
      !SSL_CTX_set1_curves_list(ctx.get(), args_map["-curves"].c_str())) {
    fprintf(stderr, "Failed setting curves list\n");
    return false;
  }

  uint16_t max_version = TLS1_3_VERSION;
  if (args_map.count("-max-version") != 0 &&
      !VersionFromString(&max_version, args_map["-max-version"])) {
    fprintf(stderr, "Unknown protocol version: '%s'\n",
            args_map["-max-version"].c_str());
    return false;
  }

  if (!SSL_CTX_set_max_proto_version(ctx.get(), max_version)) {
    return false;
  }

  if (args_map.count("-min-version") != 0) {
    uint16_t version;
    if (!VersionFromString(&version, args_map["-min-version"])) {
      fprintf(stderr, "Unknown protocol version: '%s'\n",
              args_map["-min-version"].c_str());
      return false;
    }
    if (!SSL_CTX_set_min_proto_version(ctx.get(), version)) {
      return false;
    }
  }

  if (args_map.count("-ocsp-response") != 0 &&
      !LoadOCSPResponse(ctx.get(), args_map["-ocsp-response"].c_str())) {
    fprintf(stderr, "Failed to load OCSP response: %s\n",
            args_map["-ocsp-response"].c_str());
    return false;
  }

  if (args_map.count("-early-data") != 0) {
    SSL_CTX_set_early_data_enabled(ctx.get(), 1);
  }

  if (args_map.count("-debug") != 0) {
    SSL_CTX_set_info_callback(ctx.get(), InfoCallback);
  }

  if (args_map.count("-require-any-client-cert") != 0) {
    SSL_CTX_set_verify(
        ctx.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    SSL_CTX_set_cert_verify_callback(
        ctx.get(), [](X509_STORE_CTX *store, void *arg) -> int { return 1; },
        nullptr);
  }

  Listener listener;
  if (!listener.Init(args_map["-accept"])) {
    return false;
  }

  bool result = true;
  do {
    int sock = -1;
    if (!listener.Accept(&sock)) {
      return false;
    }

    BIO *bio = BIO_new_socket(sock, BIO_CLOSE);
    bssl::UniquePtr<SSL> ssl(SSL_new(ctx.get()));
    SSL_set_bio(ssl.get(), bio, bio);

    if (args_map.count("-jdk11-workaround") != 0) {
      SSL_set_jdk11_workaround(ssl.get(), 1);
    }

    int ret = SSL_accept(ssl.get());
    if (ret != 1) {
      int ssl_err = SSL_get_error(ssl.get(), ret);
      PrintSSLError(stderr, "Error while connecting", ssl_err, ret);
      result = false;
      continue;
    }

    fprintf(stderr, "Connected.\n");
    bssl::UniquePtr<BIO> bio_stderr(BIO_new_fp(stderr, BIO_NOCLOSE));
    PrintConnectionInfo(bio_stderr.get(), ssl.get());

    if (args_map.count("-www") != 0) {
      result = HandleWWW(ssl.get());
    } else {
      result = TransferData(ssl.get(), sock);
    }
  } while (args_map.count("-loop") != 0);

  return result;
}
