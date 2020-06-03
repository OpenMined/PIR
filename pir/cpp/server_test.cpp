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

#include "pir/cpp/server.h"

#include <algorithm>
#include <iostream>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "pir/cpp/client.h"
#include "pir/cpp/utils.h"

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

using namespace seal;
using namespace ::testing;
using std::int64_t;
using std::vector;

#ifdef TEST_DEBUG
#define DEBUG_OUT(x) std::cout << x << std::endl
#else
#define DEBUG_OUT(x)
#endif  // TEST_DEBUG

constexpr uint32_t POLY_MODULUS_DEGREE = 4096;

class PIRServerTest : public ::testing::Test {
 protected:
  void SetUp() { SetUpDB(10); }

  void SetUpDB(size_t dbsize, size_t dimensions = 1) {
    db_size_ = dbsize;
    db_.resize(dbsize);
    std::generate(db_.begin(), db_.end(), [n = 0]() mutable {
      ++n;
      return 4 * n + 2600;
    });

    pir_params_ = PIRParameters::Create(
        db_.size(), dimensions, generateEncryptionParams(POLY_MODULUS_DEGREE));
    auto pirdb = PIRDatabase::Create(db_, pir_params_).ValueOrDie();
    server_ = PIRServer::Create(pirdb, pir_params_).ValueOrDie();
    ASSERT_THAT(server_, NotNull());

    auto context = server_->Context()->SEALContext();
    if (!context->parameters_set()) {
      FAIL() << "Error setting encryption parameters: "
             << context->parameter_error_message();
    }
    keygen_ = make_unique<KeyGenerator>(context);
    gal_keys_ =
        keygen_->galois_keys_local(generate_galois_elts(POLY_MODULUS_DEGREE));
    encryptor_ = make_unique<Encryptor>(context, keygen_->public_key());
    evaluator_ = make_unique<Evaluator>(context);
    decryptor_ = make_unique<Decryptor>(context, keygen_->secret_key());
  }

  size_t db_size_;
  vector<std::int64_t> db_;
  GaloisKeys gal_keys_;
  shared_ptr<PIRParameters> pir_params_;
  unique_ptr<PIRServer> server_;
  unique_ptr<KeyGenerator> keygen_;
  unique_ptr<Encryptor> encryptor_;
  unique_ptr<Evaluator> evaluator_;
  unique_ptr<Decryptor> decryptor_;
};

TEST_F(PIRServerTest, TestCorrectness) {
  auto client = PIRClient::Create(pir_params_).ValueOrDie();
  const size_t desired_index = 5;
  auto request = client->CreateRequest(desired_index).ValueOrDie();
  auto response = server_->ProcessRequest(request).ValueOrDie();
  auto result = client->ProcessResponse(response).ValueOrDie();

  ASSERT_EQ(result, db_[desired_index]);
}

TEST_F(PIRServerTest, TestProcessRequest_SingleCT) {
  const size_t desired_index = 7;
  Plaintext pt(POLY_MODULUS_DEGREE);
  pt.set_zero();
  pt[desired_index] = 1;

  vector<Ciphertext> query(1);
  encryptor_->encrypt(pt, query[0]);

  Request request_proto;
  SaveCiphertexts(query, request_proto.mutable_query());
  SEALSerialize<GaloisKeys>(gal_keys_, request_proto.mutable_keys());

  auto result_or = server_->ProcessRequest(request_proto);
  ASSERT_THAT(result_or.ok(), IsTrue())
      << "Error: " << result_or.status().ToString();
  auto result = LoadCiphertexts(server_->Context()->SEALContext(),
                                result_or.ValueOrDie().reply())
                    .ValueOrDie();
  ASSERT_THAT(result, SizeIs(1));

  Plaintext result_pt;
  decryptor_->decrypt(result[0], result_pt);
  auto encoder = server_->Context()->Encoder();
  ASSERT_THAT(encoder->decode_int64(result_pt),
              Eq(db_[desired_index] * next_power_two(db_size_)));
}

TEST_F(PIRServerTest, TestProcessRequest_MultiCT) {
  SetUpDB(5000);
  const size_t desired_index = 4200;
  Plaintext pt(POLY_MODULUS_DEGREE);
  pt.set_zero();

  vector<Ciphertext> query(2);
  encryptor_->encrypt(pt, query[0]);
  pt[desired_index - POLY_MODULUS_DEGREE] = 1;
  encryptor_->encrypt(pt, query[1]);

  Request request_proto;
  SaveCiphertexts(query, request_proto.mutable_query());
  SEALSerialize<GaloisKeys>(gal_keys_, request_proto.mutable_keys());

  auto result_or = server_->ProcessRequest(request_proto);
  ASSERT_THAT(result_or.ok(), IsTrue())
      << "Error: " << result_or.status().ToString();
  auto result = LoadCiphertexts(server_->Context()->SEALContext(),
                                result_or.ValueOrDie().reply())
                    .ValueOrDie();
  ASSERT_THAT(result, SizeIs(1));

  Plaintext result_pt;
  decryptor_->decrypt(result[0], result_pt);
  auto encoder = server_->Context()->Encoder();
  DEBUG_OUT("Expected DB value " << db_[desired_index]);
  DEBUG_OUT("Expected m " << next_power_two(db_size_ - POLY_MODULUS_DEGREE));
  ASSERT_THAT(
      encoder->decode_int64(result_pt),
      Eq(db_[desired_index] * next_power_two(db_size_ - POLY_MODULUS_DEGREE)));
}

// Make sure that if we get a weird request from client nothing explodes.
TEST_F(PIRServerTest, TestProcessRequestZeroInput) {
  Plaintext pt(POLY_MODULUS_DEGREE);
  pt.set_zero();

  vector<Ciphertext> query(1);
  encryptor_->encrypt(pt, query[0]);

  Request request_proto;
  SaveCiphertexts(query, request_proto.mutable_query());
  SEALSerialize<GaloisKeys>(gal_keys_, request_proto.mutable_keys());

  auto result_or = server_->ProcessRequest(request_proto);
  ASSERT_THAT(result_or.ok(), IsTrue());
  auto result = LoadCiphertexts(server_->Context()->SEALContext(),
                                result_or.ValueOrDie().reply())
                    .ValueOrDie();

  ASSERT_THAT(result, SizeIs(1));

  Plaintext result_pt;
  decryptor_->decrypt(result[0], result_pt);
  auto encoder = server_->Context()->Encoder();
  ASSERT_THAT(encoder->decode_int64(result_pt), 0);
}

TEST_F(PIRServerTest, TestProcessRequest_2Dim) {
  SetUpDB(82, 2);
  const size_t desired_index = 42;
  Plaintext pt(POLY_MODULUS_DEGREE);
  pt.set_zero();
  // select 4th row
  pt[4] = 1;
  // select 6th column (after 10-item selection vector for rows)
  pt[16] = 1;

  vector<Ciphertext> query(1);
  encryptor_->encrypt(pt, query[0]);

  Request request_proto;
  SaveCiphertexts(query, request_proto.mutable_query());
  SEALSerialize<GaloisKeys>(gal_keys_, request_proto.mutable_keys());

  auto result_or = server_->ProcessRequest(request_proto);
  ASSERT_THAT(result_or.ok(), IsTrue())
      << "Error: " << result_or.status().ToString();

  auto result = LoadCiphertexts(server_->Context()->SEALContext(),
                                result_or.ValueOrDie().reply())
                    .ValueOrDie();
  ASSERT_THAT(result, SizeIs(1));

  Plaintext result_pt;
  decryptor_->decrypt(result[0], result_pt);
  auto encoder = server_->Context()->Encoder();
  ASSERT_THAT(encoder->decode_int64(result_pt),
              Eq(db_[desired_index] * 32 * 32));
}

class SubstituteOperatorTest
    : public PIRServerTest,
      public testing::WithParamInterface<tuple<string, uint32_t, string>> {};

TEST_P(SubstituteOperatorTest, SubstituteExamples) {
  Plaintext input_pt(get<0>(GetParam()));
  DEBUG_OUT("Input PT: " << input_pt.to_string());

  Ciphertext ct;
  encryptor_->encrypt(input_pt, ct);

  auto k = get<1>(GetParam());
  GaloisKeys gal_keys = keygen_->galois_keys_local(vector<uint32_t>({k}));
  server_->substitute_power_x_inplace(ct, k, gal_keys);

  Plaintext result_pt;
  decryptor_->decrypt(ct, result_pt);
  DEBUG_OUT("Result PT: " << result_pt.to_string());

  Plaintext expected_pt(get<2>(GetParam()));
  DEBUG_OUT("Expected PT: " << expected_pt.to_string());
  ASSERT_THAT(result_pt, Eq(expected_pt));
}

INSTANTIATE_TEST_SUITE_P(
    Substitutions, SubstituteOperatorTest,
    testing::Values(make_tuple("42", 3, "42"), make_tuple("1x^1", 5, "1x^5"),
                    make_tuple("6x^2", 3, "6x^6"),
                    make_tuple("1x^1", POLY_MODULUS_DEGREE + 1, "FC000x^1"),
                    make_tuple("1x^4", POLY_MODULUS_DEGREE + 1, "1x^4"),
                    make_tuple("1x^8", POLY_MODULUS_DEGREE / 2 + 1, "1x^8"),
                    make_tuple("1x^8", POLY_MODULUS_DEGREE / 4 + 1, "1x^8"),
                    make_tuple("1x^8", POLY_MODULUS_DEGREE / 8 + 1, "FC000x^8"),
                    make_tuple("77x^4095", 3, "77x^4093"),
                    make_tuple("1x^4095", POLY_MODULUS_DEGREE + 1,
                               "FC000x^4095"),
                    make_tuple("4x^4 + 33x^3 + 222x^2 + 19x^1 + 42",
                               POLY_MODULUS_DEGREE + 1,
                               "4x^4 + FBFCEx^3 + 222x^2 + FBFE8x^1 + 42")));

class MultiplyInversePowerXTest
    : public PIRServerTest,
      public testing::WithParamInterface<tuple<string, uint32_t, string>> {};

TEST_P(MultiplyInversePowerXTest, MultiplyInversePowerXExamples) {
  Plaintext input_pt(get<0>(GetParam()));
  DEBUG_OUT("Input PT: " << input_pt.to_string());

  Ciphertext ct;
  encryptor_->encrypt(input_pt, ct);

  auto k = get<1>(GetParam());
  Ciphertext result_ct;
  server_->multiply_inverse_power_of_x(ct, k, result_ct);

  Plaintext result_pt;
  decryptor_->decrypt(result_ct, result_pt);
  DEBUG_OUT("Result PT: " << result_pt.to_string());

  Plaintext expected_pt(get<2>(GetParam()));
  DEBUG_OUT("Expected PT: " << expected_pt.to_string());
  ASSERT_THAT(result_pt, Eq(expected_pt));
}

INSTANTIATE_TEST_SUITE_P(InversePowersOfX, MultiplyInversePowerXTest,
                         testing::Values(make_tuple("42x^1", 1, "42"),
                                         make_tuple("42x^42", 41, "42x^1"),
                                         make_tuple("1x^4 + 1x^3 + 1x^1", 1,
                                                    "1x^3 + 1x^2 + 1"),
                                         make_tuple("1x^16 + 1x^12 + 1x^8", 4,
                                                    "1x^12 + 1x^8 + 1x^4")));

class ObliviousExpansionTest
    : public PIRServerTest,
      public testing::WithParamInterface<tuple<string, vector<string>>> {};

TEST_P(ObliviousExpansionTest, ObliviousExpansionExamples) {
  Plaintext input_pt(get<0>(GetParam()));
  DEBUG_OUT("Input PT: " << input_pt.to_string());

  Ciphertext ct;
  encryptor_->encrypt(input_pt, ct);

  auto expected = get<1>(GetParam());
  auto results_or = server_->oblivious_expansion(
      ct, expected.size(),
      keygen_->galois_keys_local(generate_galois_elts(POLY_MODULUS_DEGREE)));

  ASSERT_THAT(results_or.ok(), IsTrue());
  auto results = results_or.ValueOrDie();

  vector<Plaintext> results_pt(results.size());
  for (size_t i = 0; i < results.size(); ++i) {
    decryptor_->decrypt(results[i], results_pt[i]);
    DEBUG_OUT("Result PT[" << i << "]: " << results_pt[i].to_string());
  }

  vector<Plaintext> expected_pt(expected.size());
  for (size_t i = 0; i < expected_pt.size(); ++i) {
    expected_pt[i] = Plaintext(expected[i]);
    DEBUG_OUT("Expected PT[" << i << "]: " << expected_pt[i].to_string());
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

class ObliviousExpansionTestMultiCT
    : public PIRServerTest,
      public testing::WithParamInterface<tuple<size_t, size_t, uint64_t>> {};

TEST_P(ObliviousExpansionTestMultiCT, MultiCTExamples) {
  const auto num_items = get<0>(GetParam());
  const auto index = get<1>(GetParam());
  const auto expected_value = get<2>(GetParam());

  vector<Plaintext> input_pt(num_items / POLY_MODULUS_DEGREE + 1,
                             Plaintext(POLY_MODULUS_DEGREE));
  input_pt[index / POLY_MODULUS_DEGREE][index % POLY_MODULUS_DEGREE] = 1;
  vector<Ciphertext> input_ct(input_pt.size());
  for (size_t i = 0; i < input_pt.size(); ++i) {
    DEBUG_OUT("Input PT[" << i << "]: " << input_pt[i].to_string());
    encryptor_->encrypt(input_pt[i], input_ct[i]);
  }

  auto results_or = server_->oblivious_expansion(
      input_ct, num_items,
      keygen_->galois_keys_local(generate_galois_elts(POLY_MODULUS_DEGREE)));

  ASSERT_THAT(results_or.ok(), IsTrue())
      << "Error: " << results_or.status().ToString();
  auto results = results_or.ValueOrDie();
  ASSERT_THAT(results, SizeIs(num_items));

  for (size_t i = 0; i < results.size(); ++i) {
    Plaintext result_pt;
    decryptor_->decrypt(results[i], result_pt);
    const auto exp = (i == index) ? expected_value : 0;
    EXPECT_THAT(result_pt.coeff_count(), Eq(1))
        << "i = " << i << ", pt = " << result_pt.to_string();
    EXPECT_THAT(result_pt[0], Eq(exp))
        << "i = " << i << ", pt = " << result_pt.to_string();
  }
}

INSTANTIATE_TEST_SUITE_P(
    ObliviousExpansionMultiCT, ObliviousExpansionTestMultiCT,
    testing::Values(make_tuple(100, 42, 128), make_tuple(100, 0, 128),
                    make_tuple(100, 99, 128), make_tuple(4096, 3007, 4096),
                    make_tuple(5000, 4095, 4096),
                    make_tuple(5000, 4200, 1024)));

}  // namespace
}  // namespace pir
