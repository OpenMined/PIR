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

#include "server.h"

#include <gmock/gmock.h>
#include <seal/util/polyarithsmallmod.h>

#include <algorithm>
#include <iostream>
#include <vector>

#include "client.h"
#include "gtest/gtest.h"

namespace pir {
namespace {

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

using namespace ::testing;

class PIRServerTest : public ::testing::Test {
 protected:
};

TEST_F(PIRServerTest, TestCorrectness) {
  constexpr std::size_t dbsize = 10;
  std::vector<std::int64_t> db(dbsize, 0);

  std::generate(db.begin(), db.end(), [n = 0]() mutable {
    ++n;
    return 4 * n;
  });

  auto params = PIRParameters::Create(db.size());
  auto pirdb = PIRDatabase::Create(db, params).ValueOrDie();
  auto server_ = PIRServer::Create(pirdb, params).ValueOrDie();

  ASSERT_TRUE(server_ != nullptr);

  for (auto& client_ :
       {PIRClient::Create(PIRParameters::Create(dbsize)).ValueOrDie()}) {
    size_t desiredIndex = 5;
    auto payload = client_->CreateRequest(desiredIndex).ValueOrDie();
    auto response = server_->ProcessRequest(payload).ValueOrDie();
    auto out = client_->ProcessResponse(response).ValueOrDie();

    ASSERT_TRUE(out == db[desiredIndex]);
  }
}

using namespace seal;

class OperatorTestBase : public ::testing::Test {
 protected:
  void SetUp() {
    std::vector<std::int64_t> db(1, 42);
    pir_params_ = PIRParameters::Create(db.size());
    auto pirdb = PIRDatabase::Create(db, pir_params_).ValueOrDie();
    server_ = PIRServer::Create(pirdb, pir_params_).ValueOrDie();
    ASSERT_THAT(server_, NotNull());

    auto context = server_->Context()->SEALContext();
    if (!context->parameters_set()) {
      FAIL() << "Error setting encryption parameters: "
             << context->parameter_error_message();
    }
    keygen_ = make_unique<KeyGenerator>(context);
    encryptor_ = make_unique<Encryptor>(context, keygen_->public_key());
    evaluator_ = make_unique<Evaluator>(context);
    decryptor_ = make_unique<Decryptor>(context, keygen_->secret_key());
  }

  void TearDown() {}

  shared_ptr<PIRParameters> pir_params_;
  unique_ptr<PIRServer> server_;
  unique_ptr<KeyGenerator> keygen_;
  unique_ptr<Encryptor> encryptor_;
  unique_ptr<Evaluator> evaluator_;
  unique_ptr<Decryptor> decryptor_;
};

class SubstituteOperatorTest
    : public OperatorTestBase,
      public testing::WithParamInterface<tuple<string, uint32_t, string>> {};

TEST_P(SubstituteOperatorTest, SubstituteExamples) {
  Plaintext input_pt(get<0>(GetParam()));
  cout << "Input PT: " << input_pt.to_string() << endl;

  Ciphertext ct;
  encryptor_->encrypt(input_pt, ct);

  auto k = get<1>(GetParam());
  GaloisKeys gal_keys = keygen_->galois_keys_local(vector<uint32_t>({k}));
  server_->substitute_power_x_inplace(ct, k, gal_keys);

  Plaintext result_pt;
  decryptor_->decrypt(ct, result_pt);
  cout << "Result PT: " << result_pt.to_string() << endl;

  Plaintext expected_pt(get<2>(GetParam()));
  cout << "Expected PT: " << expected_pt.to_string() << endl;
  ASSERT_THAT(result_pt, Eq(expected_pt));
}

INSTANTIATE_TEST_SUITE_P(
    Substitutions, SubstituteOperatorTest,
    testing::Values(
        make_tuple("42", 3, "42"), make_tuple("1x^1", 5, "1x^5"),
        make_tuple("6x^2", 3, "6x^6"),
        make_tuple("1x^1", DEFAULT_POLY_MODULUS_DEGREE + 1, "FC000x^1"),
        make_tuple("1x^4", DEFAULT_POLY_MODULUS_DEGREE + 1, "1x^4"),
        make_tuple("1x^8", DEFAULT_POLY_MODULUS_DEGREE / 2 + 1, "1x^8"),
        make_tuple("1x^8", DEFAULT_POLY_MODULUS_DEGREE / 4 + 1, "1x^8"),
        make_tuple("1x^8", DEFAULT_POLY_MODULUS_DEGREE / 8 + 1, "FC000x^8"),
        make_tuple("77x^4095", 3, "77x^4093"),
        make_tuple("1x^4095", DEFAULT_POLY_MODULUS_DEGREE + 1, "FC000x^4095"),
        make_tuple("4x^4 + 33x^3 + 222x^2 + 19x^1 + 42",
                   DEFAULT_POLY_MODULUS_DEGREE + 1,
                   "4x^4 + FBFCEx^3 + 222x^2 + FBFE8x^1 + 42")));

class MultiplyPowerXTest
    : public OperatorTestBase,
      public testing::WithParamInterface<tuple<string, uint32_t, string>> {};

TEST_P(MultiplyPowerXTest, MultiplyPowerXExamples) {
  Plaintext input_pt(get<0>(GetParam()));
  cout << "Input PT: " << input_pt.to_string() << endl;

  Ciphertext ct;
  encryptor_->encrypt(input_pt, ct);

  auto k = get<1>(GetParam());
  Ciphertext result_ct;
  server_->multiply_power_of_x(ct, k, result_ct);

  Plaintext result_pt;
  decryptor_->decrypt(result_ct, result_pt);
  cout << "Result PT: " << result_pt.to_string() << endl;

  Plaintext expected_pt(get<2>(GetParam()));
  cout << "Expected PT: " << expected_pt.to_string() << endl;
  ASSERT_THAT(result_pt, Eq(expected_pt));
}

INSTANTIATE_TEST_SUITE_P(
    PowersOfX, MultiplyPowerXTest,
    testing::Values(make_tuple("42", 1, "42x^1"),
                    make_tuple("42x^1", 41, "42x^42"),
                    make_tuple("1x^4 + 1x^3 + 1x^1", 3, "1x^7 + 1x^6 + 1x^4"),
                    make_tuple("77x^1", -1, "77"),
                    make_tuple("1x^4 + 1x^3 + 1x^1", -1, "1x^3 + 1x^2 + 1"),
                    make_tuple("1x^16 + 1x^12 + 1x^8", -4,
                               "1x^12 + 1x^8 + 1x^4")));

class ObliviousExpansionTest
    : public OperatorTestBase,
      public testing::WithParamInterface<tuple<string, vector<string>>> {
 protected:
  vector<uint32_t> generate_galois_elts(uint64_t N) {
    const size_t logN = ceil(log2(N));
    vector<uint32_t> galois_elts(logN);
    for (size_t i = 0; i < logN; ++i) {
      uint64_t two_exp_i = ((uint64_t)1) << i;
      galois_elts[i] = (N / two_exp_i) + 1;
    }
    return galois_elts;
  }
};

TEST_P(ObliviousExpansionTest, ObliviousExpansionExamples) {
  Plaintext input_pt(get<0>(GetParam()));
  cout << "Input PT: " << input_pt.to_string() << endl;

  Ciphertext ct;
  encryptor_->encrypt(input_pt, ct);

  auto expected = get<1>(GetParam());
  auto results = server_->oblivious_expansion(
      ct, expected.size(),
      keygen_->galois_keys_local(
          generate_galois_elts(DEFAULT_POLY_MODULUS_DEGREE)));

  vector<Plaintext> results_pt(results.size());
  for (size_t i = 0; i < results.size(); ++i) {
    decryptor_->decrypt(results[i], results_pt[i]);
    cout << "Result PT[" << i << "]: " << results_pt[i].to_string() << endl;
  }

  vector<Plaintext> expected_pt(expected.size());
  for (size_t i = 0; i < expected_pt.size(); ++i) {
    expected_pt[i] = Plaintext(expected[i]);
    cout << "Expected PT[" << i << "]: " << expected_pt[i].to_string() << endl;
  }

  ASSERT_THAT(results_pt, ContainerEq(expected_pt));
}

INSTANTIATE_TEST_SUITE_P(
    ObliviousExpansion, ObliviousExpansionTest,
    testing::Values(make_tuple("1", vector<string>({"2", "0"})),
                    make_tuple("1x^1", vector<string>({"0", "2"})),
                    make_tuple("3x^3 + 2x^2 + 1x^1 + 42",
                               vector<string>({"108", "4", "8", "C"})),
                    make_tuple("1x^5", vector<string>({"0", "0", "0", "0", "0",
                                                       "8"}))));

}  // namespace
}  // namespace pir
