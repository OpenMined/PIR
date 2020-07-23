#include "benchmark/benchmark.h"

#include "pir/cpp/client.h"
#include "pir/cpp/server.h"

namespace pir {

constexpr std::size_t ITEM_SIZE = 64;

std::vector<std::string> generateDB(std::size_t dbsize) {
  auto prng =
      seal::UniformRandomGeneratorFactory::DefaultFactory()->create({42});
  vector<string> db(dbsize, string(ITEM_SIZE, 0));
  for (size_t i = 0; i < dbsize; ++i) {
    prng->generate(db[i].size(),
                   reinterpret_cast<seal::SEAL_BYTE*>(db[i].data()));
  }
  return db;
}

void BM_DatabaseLoad(benchmark::State& state) {
  std::size_t dbsize = state.range(0);
  auto db = generateDB(dbsize);
  int64_t elements_processed = 0;
  auto params = CreatePIRParameters(db.size(), ITEM_SIZE).ValueOrDie();

  for (auto _ : state) {
    auto pirdb = PIRDatabase::Create(db, params).ValueOrDie();
    ::benchmark::DoNotOptimize(pirdb);
    elements_processed += dbsize;
  }
  state.counters["ElementsProcessed"] = benchmark::Counter(
      static_cast<double>(elements_processed), benchmark::Counter::kIsRate);
}
// Range is for the dbsize.
BENCHMARK(BM_DatabaseLoad)->RangeMultiplier(10)->Range(10, 10000);

void BM_ClientCreateRequest(benchmark::State& state) {
  std::size_t dbsize = state.range(0);
  auto db = generateDB(dbsize);

  auto params = CreatePIRParameters(db.size(), ITEM_SIZE).ValueOrDie();
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
BENCHMARK(BM_ClientCreateRequest)->RangeMultiplier(10)->Range(10, 1000);

void BM_ServerProcessRequest(benchmark::State& state) {
  std::size_t dbsize = state.range(0);
  auto db = generateDB(dbsize);

  auto params = CreatePIRParameters(db.size(), ITEM_SIZE).ValueOrDie();
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
BENCHMARK(BM_ServerProcessRequest)->RangeMultiplier(10)->Range(10, 1000);

void BM_ClientProcessResponseInteger(benchmark::State& state) {
  std::size_t dbsize = state.range(0);
  auto db = generateDB(dbsize);

  auto params = CreatePIRParameters(db.size(), ITEM_SIZE).ValueOrDie();
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
BENCHMARK(BM_ClientProcessResponseInteger)
    ->RangeMultiplier(10)
    ->Range(10, 1000);

void BM_PayloadSize(benchmark::State& state) {
  std::size_t dbsize = state.range(0);
  auto db = generateDB(dbsize);

  auto params = CreatePIRParameters(db.size(), ITEM_SIZE).ValueOrDie();
  auto pirdb = PIRDatabase::Create(db, params).ValueOrDie();
  auto server_ = PIRServer::Create(pirdb, params).ValueOrDie();

  int64_t total_bytes = 0;
  int64_t network_bytes = 0;

  auto client_ = PIRClient::Create(params).ValueOrDie();
  std::vector<size_t> desiredIndex = {dbsize - 1};

  auto request = client_->CreateRequest(desiredIndex).ValueOrDie();
  int64_t raw_request = request.ByteSizeLong();

  for (auto _ : state) {
    total_bytes += raw_request;
    auto request = client_->CreateRequest(desiredIndex).ValueOrDie();
    ::benchmark::DoNotOptimize(request);
    network_bytes += request.ByteSizeLong();
    auto response = server_->ProcessRequest(request).ValueOrDie();
    ::benchmark::DoNotOptimize(response);
    auto out = client_->ProcessResponseInteger(response).ValueOrDie();
    ::benchmark::DoNotOptimize(out);
  }
  state.counters["NetworkBytes"] = benchmark::Counter(
      static_cast<double>(network_bytes), benchmark::Counter::kIsRate);
  state.counters["RawBytes"] = benchmark::Counter(
      static_cast<double>(total_bytes), benchmark::Counter::kIsRate);
}
// Range is for the dbsize.
BENCHMARK(BM_PayloadSize)->RangeMultiplier(10)->Range(10, 1000);

}  // namespace pir
