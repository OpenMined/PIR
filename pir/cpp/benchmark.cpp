#include "benchmark/benchmark.h"

#include <iostream>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "pir/cpp/client.h"
#include "pir/cpp/server.h"
#include "pir/cpp/status_asserts.h"
#include "pir/cpp/test_base.h"
#include "seal/seal.h"

namespace pir {

using namespace ::testing;

constexpr uint32_t ITEM_SIZE = 288;
constexpr uint32_t DIMENSIONS = 2;
constexpr uint32_t POLY_MOD_DEGREE = 8192;
constexpr uint32_t PLAIN_MOD_BITS = 42;
constexpr uint32_t BITS_PER_COEFF = 0;

using std::cout;
using std::endl;

class PIRFixture : public benchmark::Fixture, public PIRTestingBase {
 public:
  void SetUpDb(const ::benchmark::State& state) {
    SetUpParams(state.range(0), ITEM_SIZE, DIMENSIONS, POLY_MOD_DEGREE,
                PLAIN_MOD_BITS, BITS_PER_COEFF);
    GenerateDB();
    SetUpSealTools();

    client_ = PIRClient::Create(pir_params_).ValueOrDie();
    server_ = PIRServer::Create(pir_db_, pir_params_).ValueOrDie();
    ASSERT_THAT(client_, NotNull());
    ASSERT_THAT(server_, NotNull());
  }

  uint32_t GenerateRandomIndex() {
    static auto prng =
        seal::UniformRandomGeneratorFactory::DefaultFactory()->create({42});
    return prng->generate() % (db_size_);
  }

  unique_ptr<PIRClient> client_;
  unique_ptr<PIRServer> server_;
};

BENCHMARK_DEFINE_F(PIRFixture, SetupDb)(benchmark::State& st) {
  for (auto _ : st) {
    SetUpDb(st);
  }
}

BENCHMARK_DEFINE_F(PIRFixture, ClientCreateRequest)(benchmark::State& st) {
  SetUpDb(st);
  for (auto _ : st) {
    ASSIGN_OR_FAIL(auto request,
                   client_->CreateRequest({GenerateRandomIndex()}));
    ::benchmark::DoNotOptimize(request);
  }
}

BENCHMARK_DEFINE_F(PIRFixture, ServerProcessRequest)(benchmark::State& st) {
  SetUpDb(st);
  ASSIGN_OR_FAIL(auto request, client_->CreateRequest({GenerateRandomIndex()}));
  for (auto _ : st) {
    ASSIGN_OR_FAIL(auto response, server_->ProcessRequest(request));
    ::benchmark::DoNotOptimize(response);
  }
}

BENCHMARK_DEFINE_F(PIRFixture, ClientProcessResponse)(benchmark::State& st) {
  SetUpDb(st);
  vector<size_t> desired_indices = {GenerateRandomIndex()};
  ASSIGN_OR_FAIL(auto request, client_->CreateRequest(desired_indices));
  ASSIGN_OR_FAIL(auto response, server_->ProcessRequest(request));

  for (auto _ : st) {
    ASSIGN_OR_FAIL(auto results,
                   client_->ProcessResponse(desired_indices, response));
    ASSERT_EQ(results.size(), desired_indices.size());
    for (size_t i = 0; i < results.size(); ++i) {
      ASSERT_EQ(results[i], string_db_[desired_indices[i]]) << "i = " << i;
    }
  }
}

BENCHMARK_REGISTER_F(PIRFixture, SetupDb)
    ->RangeMultiplier(2)
    ->Range(1 << 8, 1 << 16);
BENCHMARK_REGISTER_F(PIRFixture, ClientCreateRequest)
    ->RangeMultiplier(2)
    ->Range(1 << 8, 1 << 16);
BENCHMARK_REGISTER_F(PIRFixture, ServerProcessRequest)
    ->RangeMultiplier(2)
    ->Range(1 << 8, 1 << 16);
BENCHMARK_REGISTER_F(PIRFixture, ClientProcessResponse)
    ->RangeMultiplier(2)
    ->Range(1 << 8, 1 << 16);

}  // namespace pir
