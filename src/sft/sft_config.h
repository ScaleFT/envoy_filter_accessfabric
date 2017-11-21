#pragma once

#include "common/common/logger.h"
#include "common/http/rest_api_fetcher.h"
#include "envoy/json/json_object.h"
#include "server/config/network/http_connection_manager.h"
#include "envoy/stats/stats_macros.h"

#include "jwt.h"

#include <map>

namespace Envoy {
namespace Http {
namespace Sft {

// clang-format off
#define ALL_SFT_STATS(COUNTER, GAUGE)                                                       \
  COUNTER(jwks_fetch_failed)                                                                \
  COUNTER(jwks_fetch_success)                                                               \
  COUNTER(jwt_rejected)                                                                     \
  COUNTER(jwt_accepted)
// clang-format on

struct SftStats {
  ALL_SFT_STATS(GENERATE_COUNTER_STRUCT, GENERATE_GAUGE_STRUCT)
};

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
class SFTConfig : public Http::AsyncClient::Callbacks, public Logger::Loggable<Logger::Id::http> {
public:
  SFTConfig(const Json::Object& config, ThreadLocal::SlotAllocator& tls,
            Upstream::ClusterManager& cm, Event::Dispatcher& dispatcher, Stats::Scope& scope,
            Runtime::RandomGenerator& random);
  ~SFTConfig();
  const JWKS& jwks();
  const LowerCaseString headerKey = LowerCaseString("authenticated-user-jwt");

  const SftStats& stats() { return stats_; }
  static SftStats generateStats(const std::string& prefix, Stats::Scope& scope);

  std::string jwks_api_path_;
  std::string allowed_issuer_;
  std::vector<std::string> allowed_audiences_;

protected:
  const std::string remote_cluster_name_;
  Upstream::ClusterManager& cm_;

private:
  // Http::AsyncClient::Callbacks
  void onSuccess(Http::MessagePtr&& response) override;
  void onFailure(Http::AsyncClient::FailureReason reason) override;

  void refresh();
  void requestComplete(std::chrono::milliseconds interval);
  void requestFailed(Http::AsyncClient::FailureReason reason);

  int retry_count_;
  Runtime::RandomGenerator& random_;
  const std::chrono::milliseconds refresh_interval_;
  Event::TimerPtr refresh_timer_;
  Http::AsyncClient::Request* active_request_{};

  const SftStats stats_;
  ThreadLocal::SlotPtr tls_;
};

} // namespace Sft
} // namespace Http
} // namespace Envoy