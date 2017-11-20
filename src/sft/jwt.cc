#include "jwt.h"

#include "common/common/assert.h"
#include "common/common/base64.h"
#include "common/common/utility.h"
#include "common/json/json_loader.h"
#include "envoy/json/json_object.h"
#include "openssl/bn.h"
#include "openssl/evp.h"
#include "openssl/rsa.h"

#include <algorithm>
#include <cassert>
#include <map>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace Envoy {
namespace Http {
namespace Sft {

// Pad properly, substitute url safe chars for regular Base64, pass to Envoy's
// Base64 decode.
static std::string urlsafeBase64Decode(const std::string& base64) {
  const size_t padding = (4 - base64.size() % 4) % 4;
  std::string input = base64 + std::string(padding, '=');

  for (char& c : input) {
    switch (c) {
    case '-':
      c = '+';
      break;
    case '_':
      c = '/';
      break;
    default:
      break;
    }
  }

  return Base64::decode(input);
}

// Signature block is 2 numbers url safe base64 encoded, the first half is
// R, the latter half S. We pass that with the relevant public key X and Y
// initialized with the correct sha/curve functions to do the verification.
static inline std::string signatureToASN(const std::string& signature) {
  ecdsa_sig sig;
  BIGNUM* r = sig.r();
  BIGNUM* s = sig.s();

  r = BN_bin2bn(castToUChar(signature.substr(0, signature.size() / 2)), signature.size() / 2, r);
  s = BN_bin2bn(castToUChar(signature.substr(signature.size() / 2)), signature.size() / 2, s);
  unsigned char* p = nullptr;
  size_t len;
  len = i2d_ECDSA_SIG(sig, &p);
  std::string asan = std::string{reinterpret_cast<char const*>(p), len};
  if (p) {
    OPENSSL_free(p);
  }
  return asan;
}

// TODO(morgabra) Make this a class
// TODO(morgabra) Support RSA?
// TODO(morgabra) Proper error handling, surface useful errors.
const std::shared_ptr<evp_pkey> ParseECPublicKey(const Json::ObjectSharedPtr& jwk) {
  std::string crv_s = jwk->getString("crv", "");
  int crv = curveTypeToNID(crv_s);
  if (crv == -1) {
    return nullptr;
  }

  std::string x = urlsafeBase64Decode(jwk->getString("x", ""));
  std::string y = urlsafeBase64Decode(jwk->getString("y", ""));

  if (x == "" || y == "") {
    return nullptr;
  }

  // New EC_KEY
  ec key(crv);
  if (!key) {
    ERR_print_errors_fp(stderr);
    return nullptr;
  }

  // Set key params
  bn bx(x);
  bn by(y);
  if (EC_KEY_set_public_key_affine_coordinates(key, bx, by) != 1) {
    ERR_print_errors_fp(stderr);
    return nullptr;
  }

  // Wrap in EVP_PKEY
  // TODO(morgabra) Do shared pointers get destructors called when you
  // remove them from a collection? (i.e. a map)
  std::shared_ptr<evp_pkey> pkey = std::make_shared<evp_pkey>();
  if (EVP_PKEY_set1_EC_KEY(*pkey, key) != 1) {
    ERR_print_errors_fp(stderr);
    return nullptr;
  }

  return pkey;
}

// TODO(morgabra) Support RSA?
// TODO(morgabra) Should we do verification of claims here?
// TODO(morgabra) Proper error handling, surface useful errors.
Jwt::Jwt(const std::string& jwt) {
  std::vector<std::string> jwt_split = StringUtil::split(jwt, '.');
  if (jwt_split.size() != 3) {
    parsed_ = false;
    return;
  }

  // Parse header json
  header_raw_ = jwt_split[0];
  try {
    header_ = Json::Factory::loadFromString(urlsafeBase64Decode(header_raw_));
  } catch (...) {
    parsed_ = false;
    return;
  }

  // Parse payload json
  payload_raw_ = jwt_split[1];
  try {
    payload_ = Json::Factory::loadFromString(urlsafeBase64Decode(payload_raw_));
  } catch (...) {
    parsed_ = false;
    return;
  }

  // Set up signature
  signature_raw_ = jwt_split[2];
  signature_ = urlsafeBase64Decode(jwt_split[2]);
  if (signature_ == "") {
    parsed_ = false;
    return;
  }

  parsed_ = true;
}

// TODO(morgabra) Support RSA?
// TODO(morgabra) Should we do verification of claims here?
// TODO(morgabra) Proper error handling, surface useful errors.
bool Jwt::VerifySignature(const std::shared_ptr<evp_pkey> pkey) {
  if (!parsed_) {
    return false;
  }

  std::string signed_data = header_raw_ + '.' + payload_raw_;
  fprintf(stderr, "JWT: verifying signed data %s\n", signed_data.c_str());

  std::string alg = header_->getString("alg");
  const EVP_MD* md = hashFuncToEVP(alg);
  if (!md) {
    return false;
  }

  evp_md_ctx evp_ctx;
  if (EVP_DigestVerifyInit(evp_ctx, nullptr, md, nullptr, *pkey) != 1) {
    fprintf(stderr, "JWT: EVP_DigestVerifyInit failed\n");
    ERR_print_errors_fp(stderr);
    return false;
  }
  if (EVP_DigestVerifyUpdate(evp_ctx, castToUChar(signed_data), signed_data.size()) != 1) {
    fprintf(stderr, "JWT: EVP_DigestVerifyUpdate failed\n");
    ERR_print_errors_fp(stderr);
    return false;
  }
  std::string asn = signatureToASN(signature_);
  if (EVP_DigestVerifyFinal(evp_ctx, castToUChar(asn), asn.size()) != 1) {
    fprintf(stderr, "JWT: EVP_DigestVerifyFinal failed\n");
    ERR_print_errors_fp(stderr);
    return false;
  }
  return true;
}

// Returns the parsed header.
Json::ObjectSharedPtr Jwt::Header() { return header_; }

// Returns the parsed payload.
Json::ObjectSharedPtr Jwt::Payload() { return payload_; }

} // namespace Sft
} // namespace Http
} // namespace Envoy