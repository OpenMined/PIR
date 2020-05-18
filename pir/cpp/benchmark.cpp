#include "benchmark/benchmark.h"

#include "client.h"
#include "server.h"

namespace pir {
namespace {

std::vector<std::int64_t> generateDB(std::size_t dbsize) {
  std::vector<std::int64_t> db(dbsize, 0);

  std::generate(db.begin(), db.end(), [n = 0]() mutable {
    ++n;
    return 4 * n;
  });

  return db;
}

void BM_ServerLoad(benchmark::State& state) {
  std::size_t dbsize = state.range(0);
  auto db = generateDB(dbsize);
  int64_t elements_processed = 0;

  for (auto _ : state) {
    auto server_ = PIRServer::Create(db).ValueOrDie();
    ::benchmark::DoNotOptimize(server_);
    elements_processed += dbsize;
  }
  state.counters["ElementsProcessed"] = benchmark::Counter(
      static_cast<double>(elements_processed), benchmark::Counter::kIsRate);
}  // namespace
// Range is for the dbsize.
BENCHMARK(BM_ServerLoad)->RangeMultiplier(10)->Range(10, 10000);

void BM_ClientCreateRequest(benchmark::State& state) {
  std::size_t dbsize = state.range(0);
  auto db = generateDB(dbsize);

  auto server_ = PIRServer::Create(db).ValueOrDie();

  auto client_ = PIRClient::Create(PIRParameters::Create(dbsize)).ValueOrDie();
  size_t desiredIndex = dbsize - 1;

  int64_t elements_processed = 0;

  for (auto _ : state) {
    auto payload = client_->CreateRequest(desiredIndex).ValueOrDie();
    ::benchmark::DoNotOptimize(payload);
    elements_processed += dbsize;
  }
  state.counters["ElementsProcessed"] = benchmark::Counter(
      static_cast<double>(elements_processed), benchmark::Counter::kIsRate);
}  // namespace
// Range is for the dbsize.
BENCHMARK(BM_ClientCreateRequest)->RangeMultiplier(10)->Range(10, 10000);

void BM_ServerProcessRequest(benchmark::State& state) {
  std::size_t dbsize = state.range(0);
  auto db = generateDB(dbsize);

  auto server_ = PIRServer::Create(db).ValueOrDie();

  auto client_ = PIRClient::Create(PIRParameters::Create(dbsize)).ValueOrDie();
  size_t desiredIndex = dbsize - 1;
  auto payload = client_->CreateRequest(desiredIndex).ValueOrDie();

  int64_t elements_processed = 0;

  for (auto _ : state) {
    auto response = server_->ProcessRequest(payload).ValueOrDie();
    ::benchmark::DoNotOptimize(response);
    elements_processed += dbsize;
  }
  state.counters["ElementsProcessed"] = benchmark::Counter(
      static_cast<double>(elements_processed), benchmark::Counter::kIsRate);
}  // namespace
// Range is for the dbsize.
BENCHMARK(BM_ServerProcessRequest)->RangeMultiplier(10)->Range(10, 1000);

void BM_ClientProcessResponse(benchmark::State& state) {
  std::size_t dbsize = state.range(0);
  auto db = generateDB(dbsize);

  auto server_ = PIRServer::Create(db).ValueOrDie();

  auto client_ = PIRClient::Create(PIRParameters::Create(dbsize)).ValueOrDie();
  size_t desiredIndex = dbsize - 1;
  auto payload = client_->CreateRequest(desiredIndex).ValueOrDie();
  auto response = server_->ProcessRequest(payload).ValueOrDie();

  int64_t elements_processed = 0;

  for (auto _ : state) {
    auto out = client_->ProcessResponse(response).ValueOrDie();
    ::benchmark::DoNotOptimize(out);
    elements_processed += dbsize;
  }
  state.counters["ElementsProcessed"] = benchmark::Counter(
      static_cast<double>(elements_processed), benchmark::Counter::kIsRate);
}  // namespace
// Range is for the dbsize.
BENCHMARK(BM_ClientProcessResponse)->RangeMultiplier(10)->Range(10, 1000);

}  // namespace
}  // namespace pir
