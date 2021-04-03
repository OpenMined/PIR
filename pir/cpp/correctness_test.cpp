//
// Copyright 2020 the authors listed in CONTRIBUTORS.md
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include <algorithm>
#include <iostream>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "pir/cpp/client.h"
#include "pir/cpp/server.h"
#include "pir/cpp/status_asserts.h"
#include "pir/cpp/test_base.h"
#include "pir/cpp/utils.h"

namespace pir {
// namespace {

using std::cout;
using std::endl;
using std::get;
using std::make_tuple;
using std::make_unique;
using std::shared_ptr;
using std::string;
using std::tuple;
using std::unique_ptr;
using std::vector;

using seal::Ciphertext;
using seal::GaloisKeys;
using seal::Plaintext;
using seal::RelinKeys;

using namespace seal;
using namespace ::testing;
using std::int64_t;
using std::vector;

class PIRCorrectnessTest
    : public ::testing::TestWithParam<
          tuple<bool, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t,
                uint32_t, vector<size_t>>>,
      public PIRTestingBase {
 protected:
  void SetUp() {
    const auto use_ciphertext_multiplication = get<0>(GetParam());
    const auto poly_modulus_degree = get<1>(GetParam());
    const auto plain_mod_bits = get<2>(GetParam());
    const auto elem_size = get<3>(GetParam());
    const auto bits_per_coeff = get<4>(GetParam());
    const auto dbsize = get<5>(GetParam());
    const auto d = get<6>(GetParam());

    SetUpParams(dbsize, elem_size, d, poly_modulus_degree, plain_mod_bits,
                bits_per_coeff, use_ciphertext_multiplication);
    GenerateDB();

    client_ = *(PIRClient::Create(pir_params_));
    server_ = *(PIRServer::Create(pir_db_, pir_params_));
    ASSERT_THAT(client_, NotNull());
    ASSERT_THAT(server_, NotNull());
  }

  unique_ptr<PIRClient> client_;
  unique_ptr<PIRServer> server_;
};

TEST_P(PIRCorrectnessTest, TestCorrectness) {
  const auto desired_indices = get<7>(GetParam());
  ASSIGN_OR_FAIL(auto request, client_->CreateRequest(desired_indices));
  ASSIGN_OR_FAIL(auto response, server_->ProcessRequest(request));
  ASSIGN_OR_FAIL(auto results,
                 client_->ProcessResponse(desired_indices, response));

  ASSERT_EQ(results.size(), desired_indices.size());
  for (size_t i = 0; i < results.size(); ++i) {
    ASSERT_EQ(results[i], string_db_[desired_indices[i]]) << "i = " << i;
  }
}

INSTANTIATE_TEST_SUITE_P(
    CorrectnessTest, PIRCorrectnessTest,
    testing::Values(
        make_tuple(true, 4096, 24, 0, 0, 10, 1, vector<size_t>({0})),
        make_tuple(true, 4096, 16, 0, 10, 9, 2, vector<size_t>({1, 5})),
        make_tuple(true, 4096, 16, 0, 6, 500, 2, vector<size_t>({9, 125})),
        make_tuple(true, 8192, 42, 0, 0, 87, 2, vector<size_t>({5, 33, 86})),
        make_tuple(true, 4096, 16, 64, 10, 1200, 1,
                   vector<size_t>({0, 80, 81, 123, 777, 1199})),
        make_tuple(true, 4096, 16, 289, 10, 1200, 1,
                   vector<size_t>({0, 47, 777, 1199})),

        make_tuple(false, 4096, 24, 0, 0, 10, 1, vector<size_t>({0})),
        make_tuple(false, 4096, 24, 0, 10, 9, 2, vector<size_t>({1, 5})),
        make_tuple(false, 4096, 24, 0, 6, 500, 2, vector<size_t>({9, 125})),
        make_tuple(false, 4096, 24, 64, 10, 1200, 1,
                   vector<size_t>({0, 80, 81, 123, 777, 1199})),
        make_tuple(false, 4096, 24, 289, 10, 1200, 1,
                   vector<size_t>({0, 47, 777, 1199}))));

//}  // namespace
}  // namespace pir
