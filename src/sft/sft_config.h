#pragma once

#include "common/common/logger.h"
#include "common/http/rest_api_fetcher.h"
#include "envoy/json/json_object.h"
#include "server/config/network/http_connection_manager.h"

#include "jwt.h"

#include <map>

namespace Envoy {
namespace Http {
namespace Sft {

// Struct to hold a JSON Web Key Set.
class JWKS : public Logger::Loggable<Logger::Id::http>, public ThreadLocal::ThreadLocalObject {
public:
  bool add(const Json::ObjectSharedPtr jwk);
  std::shared_ptr<evp_pkey> get(const std::string& kid) const;

private:
  std::map<std::string, std::shared_ptr<evp_pkey>> keys_;
};

typedef std::shared_ptr<JWKS> JWKSSharedPtr;

class SFTConfig;
typedef std::shared_ptr<SFTConfig> SFTConfigSharedPtr;

// TODO(morgabra) RestApiFetcher doesn't seem to wait until the configured
// cluster is up, so it fails to fetch the first loop. Might just need to use
// AsyncClient directly - which is nice anyway because you don't have to specify
// a cluster.
class SFTConfig : public Http::RestApiFetcher, public Logger::Loggable<Logger::Id::http> {
public:
  SFTConfig(const Json::Object& config, ThreadLocal::SlotAllocator& tls,
            Upstream::ClusterManager& cm, Event::Dispatcher& dispatcher,
            Runtime::RandomGenerator& random);
  const JWKS& jwks();
  const LowerCaseString headerKey = LowerCaseString("authenticated-user-jwt");

  std::string jwks_api_path_;
  std::string allowed_issuer_;
  std::vector<std::string> allowed_audiences_;

private:
  // Http::RestApiFetcher
  void createRequest(Http::Message& request) override;
  void parseResponse(const Http::Message& response) override;
  void onFetchComplete() override {}
  void onFetchFailure(const EnvoyException* e) override;

  ThreadLocal::SlotPtr tls_;
};

} // namespace Sft
} // namespace Http
} // namespace Envoy