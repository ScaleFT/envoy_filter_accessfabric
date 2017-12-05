#pragma once

#include "common/common/base64.h"
#include "envoy/json/json_object.h"

#include "openssl/bio.h"
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/evp.h"
#include "openssl/hmac.h"
#include "openssl/pem.h"
#include "openssl/rsa.h"

#include <string>
#include <utility>
#include <vector>
/*
 * JWT/JWK
 * Borrowed heavily from: https://github.com/ibmibmibm/libjose/ and adapted to
 * be smaller (no signing) and not need any deps. (MIT License)
 *
 * TODO(morgabra) JWK class instead of a bare parse func with verify.
 * TODO(morgabra) RSA implementation.
 * TODO(morgabra) Tests/Check for leaks.
 */
namespace Envoy {
namespace Http {
namespace Sft {

// Hack(?) for passing c-style strings to OpenSSL.
static inline const uint8_t* castToUChar(const std::string& str) {
  return reinterpret_cast<const uint8_t*>(str.c_str());
}

// OpenSSL struct wrappers with destructors.
// TODO(morgabra) Do these work how I think they do? When are destructors called
// in c++?
struct bn {
  BIGNUM* _;
  bn(std::string p) : _(BN_bin2bn(castToUChar(p), p.length(), NULL)) {}
  ~bn() { BN_free(_); }
  operator BIGNUM*() { return _; }
};

struct ec {
  EC_KEY* _;
  ec(int crv) : _(EC_KEY_new_by_curve_name(crv)) {}
  ~ec() { EC_KEY_free(_); }
  operator EC_KEY*() { return _; }
};

struct bio {
  BIO* _;
  bio(BIO* _) : _(_) {}
  ~bio() { BIO_free(_); }
  operator BIO*() { return _; }
};

struct evp_pkey {
  EVP_PKEY* _;
  evp_pkey() : _(EVP_PKEY_new()) {}
  ~evp_pkey() { EVP_PKEY_free(_); }
  operator EVP_PKEY*() { return _; }
};

struct evp_md_ctx {
  EVP_MD_CTX* _;
  evp_md_ctx() : _(EVP_MD_CTX_create()) {}
  ~evp_md_ctx() { EVP_MD_CTX_destroy(_); }
  operator EVP_MD_CTX*() { return _; }
};

struct ecdsa_sig {
  ECDSA_SIG* _;
  ecdsa_sig() : _(ECDSA_SIG_new()) {}
  ~ecdsa_sig() { ECDSA_SIG_free(_); }
  BIGNUM*& r() { return _->r; }
  BIGNUM*& s() { return _->s; }
  operator ECDSA_SIG*() { return _; }
  operator ECDSA_SIG**() { return &_; }
};

// TODO(morgabra) Make this a class.
const std::shared_ptr<evp_pkey> ParseECPublicKey(const Json::ObjectSharedPtr& jwk);

class Jwt;

class Jwt {
public:
  Jwt(const std::string& jwt);
  bool IsParsed() { return parsed_; };
  bool VerifySignature(const std::shared_ptr<evp_pkey> pkey);

  // It returns a pointer to a JSON object of the header of the given JWT.
  // When the given JWT has a format error, it returns nullptr.
  // It returns the header JSON even if the signature is invalid.
  Json::ObjectSharedPtr Header();
  Json::ObjectSharedPtr Payload();

private:
  Json::ObjectSharedPtr header_;
  std::string header_raw_;
  Json::ObjectSharedPtr payload_;
  std::string payload_raw_;
  std::string signature_;
  std::string signature_raw_;

  bool parsed_;
};

} // namespace Sft
} // namespace Http
} // namespace Envoy
