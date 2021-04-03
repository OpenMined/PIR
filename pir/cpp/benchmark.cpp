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

constexpr bool USE_CIPHERTEXT_MULTIPLICATION = false;
constexpr uint32_t ITEM_SIZE = 288;
constexpr uint32_t DIMENSIONS = 2;
constexpr uint32_t POLY_MOD_DEGREE = 4096;
constexpr uint32_t PLAIN_MOD_BITS = 24;
constexpr uint32_t BITS_PER_COEFF = 0;
constexpr uint32_t QUERIES_PER_REQUEST = 1;

using std::cout;
using std::endl;

class PIRFixture : public benchmark::Fixture, public PIRTestingBase {
 public:
  void SetUpDb(const ::benchmark::State& state) {
    SetUpParams(state.range(0), ITEM_SIZE, DIMENSIONS, POLY_MOD_DEGREE,
                PLAIN_MOD_BITS, BITS_PER_COEFF, USE_CIPHERTEXT_MULTIPLICATION);
    GenerateDB();
    SetUpSealTools();

    client_ = *(PIRClient::Create(pir_params_));
    server_ = *(PIRServer::Create(pir_db_, pir_params_));
    ASSERT_THAT(client_, NotNull());
    ASSERT_THAT(server_, NotNull());
  }

  vector<size_t> GenerateRandomIndices() {
    static auto prng =
        seal::UniformRandomGeneratorFactory::DefaultFactory()->create({42});
    vector<size_t> result(QUERIES_PER_REQUEST, 0);
    for (auto& i : result) {
      i = prng->generate() % (db_size_);
    }
    return result;
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
    auto indices = GenerateRandomIndices();
    ASSIGN_OR_FAIL(auto request, client_->CreateRequest(indices));
    ::benchmark::DoNotOptimize(request);
  }
}

BENCHMARK_DEFINE_F(PIRFixture, ServerProcessRequest)(benchmark::State& st) {
  SetUpDb(st);
  auto indices = GenerateRandomIndices();
  ASSIGN_OR_FAIL(auto request, client_->CreateRequest(indices));
  for (auto _ : st) {
    ASSIGN_OR_FAIL(auto response, server_->ProcessRequest(request));
    ::benchmark::DoNotOptimize(response);
  }
}

BENCHMARK_DEFINE_F(PIRFixture, ClientProcessResponse)(benchmark::State& st) {
  SetUpDb(st);
  auto indices = GenerateRandomIndices();
  ASSIGN_OR_FAIL(auto request, client_->CreateRequest(indices));
  ASSIGN_OR_FAIL(auto response, server_->ProcessRequest(request));

  for (auto _ : st) {
    ASSIGN_OR_FAIL(auto results, client_->ProcessResponse(indices, response));
    ASSERT_EQ(results.size(), indices.size());
    for (size_t i = 0; i < results.size(); ++i) {
      ASSERT_EQ(results[i], string_db_[indices[i]]) << "i = " << i;
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
