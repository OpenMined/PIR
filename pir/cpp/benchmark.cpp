#include "benchmark/benchmark.h"

#include <random>

#include "pir/cpp/client.h"
#include "pir/cpp/server.h"

namespace pir {

constexpr std::size_t ITEM_SIZE = 0;
constexpr uint32_t DIMENSIONS = 2;

std::vector<std::int64_t> generateDB(std::size_t dbsize) {
  std::vector<std::int64_t> db(dbsize, 0);

  std::random_device rd;
  std::generate(db.begin(), db.end(), [&]() mutable { return rd(); });

  return db;
}

void BM_DatabaseLoad(benchmark::State& state) {
  std::size_t dbsize = state.range(0);
  auto db = generateDB(dbsize);
  int64_t elements_processed = 0;
  auto params =
      CreatePIRParameters(db.size(), ITEM_SIZE, DIMENSIONS).ValueOrDie();

  for (auto _ : state) {
    auto pirdb = PIRDatabase::Create(db, params).ValueOrDie();
    ::benchmark::DoNotOptimize(pirdb);
    elements_processed += dbsize;
  }
  state.counters["ElementsProcessed"] = benchmark::Counter(
      static_cast<double>(elements_processed), benchmark::Counter::kIsRate);
}
// Range is for the dbsize.
BENCHMARK(BM_DatabaseLoad)->RangeMultiplier(2)->Range(1 << 16, 1 << 16);

void BM_ClientCreateRequest(benchmark::State& state) {
  std::size_t dbsize = state.range(0);
  auto db = generateDB(dbsize);

  auto params =
      CreatePIRParameters(db.size(), ITEM_SIZE, DIMENSIONS).ValueOrDie();
  auto pirdb = PIRDatabase::Create(db, params).ValueOrDie();
  auto server_ = PIRServer::Create(pirdb, params).ValueOrDie();

  auto client_ = PIRClient::Create(params).ValueOrDie();
  std::vector<size_t> indexes = {dbsize - 1};

  int64_t elements_processed = 0;

  for (auto _ : state) {
    auto request = client_->CreateRequest(indexes).ValueOrDie();
    ::benchmark::DoNotOptimize(request);
    elements_processed += dbsize;
  }
  state.counters["ElementsProcessed"] = benchmark::Counter(
      static_cast<double>(elements_processed), benchmark::Counter::kIsRate);
}
// Range is for the dbsize.
BENCHMARK(BM_ClientCreateRequest)->RangeMultiplier(2)->Range(1 << 16, 1 << 16);

void BM_ServerProcessRequest(benchmark::State& state) {
  std::size_t dbsize = state.range(0);
  auto db = generateDB(dbsize);

  auto params =
      CreatePIRParameters(db.size(), ITEM_SIZE, DIMENSIONS).ValueOrDie();
  auto pirdb = PIRDatabase::Create(db, params).ValueOrDie();
  auto server_ = PIRServer::Create(pirdb, params).ValueOrDie();

  auto client_ = PIRClient::Create(params).ValueOrDie();
  std::vector<size_t> desiredIndex = {dbsize - 1};
  auto request = client_->CreateRequest(desiredIndex).ValueOrDie();

  int64_t elements_processed = 0;

  for (auto _ : state) {
    auto response = server_->ProcessRequest(request).ValueOrDie();
    ::benchmark::DoNotOptimize(response);
    elements_processed += dbsize;
  }
  state.counters["ElementsProcessed"] = benchmark::Counter(
      static_cast<double>(elements_processed), benchmark::Counter::kIsRate);
}
// Range is for the dbsize.
BENCHMARK(BM_ServerProcessRequest)->RangeMultiplier(2)->Range(1 << 16, 1 << 16);

void BM_ClientProcessResponse(benchmark::State& state) {
  std::size_t dbsize = state.range(0);
  auto db = generateDB(dbsize);

  auto params =
      CreatePIRParameters(db.size(), ITEM_SIZE, DIMENSIONS).ValueOrDie();
  auto pirdb = PIRDatabase::Create(db, params).ValueOrDie();
  auto server_ = PIRServer::Create(pirdb, params).ValueOrDie();

  auto client_ = PIRClient::Create(params).ValueOrDie();
  std::vector<size_t> desiredIndex = {dbsize - 1};
  auto request = client_->CreateRequest(desiredIndex).ValueOrDie();
  auto response = server_->ProcessRequest(request).ValueOrDie();

  int64_t elements_processed = 0;

  for (auto _ : state) {
    auto out = client_->ProcessResponseInteger(response).ValueOrDie();
    ::benchmark::DoNotOptimize(out);
    elements_processed += dbsize;
  }
  state.counters["ElementsProcessed"] = benchmark::Counter(
      static_cast<double>(elements_processed), benchmark::Counter::kIsRate);
}
// Range is for the dbsize.
BENCHMARK(BM_ClientProcessResponse)
    ->RangeMultiplier(2)
    ->Range(1 << 16, 1 << 16);

}  // namespace pir
