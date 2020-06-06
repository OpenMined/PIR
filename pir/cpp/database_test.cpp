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

constexpr uint32_t POLY_MODULUS_DEGREE = 4096;

class PIRDatabaseTest : public ::testing::Test {
 protected:
  void SetUp() { SetUpDB(100); }

  void SetUpDB(size_t dbsize, size_t dimensions = 1,
               uint32_t poly_modulus_degree = POLY_MODULUS_DEGREE) {
    poly_modulus_degree_ = poly_modulus_degree;
    db_size_ = dbsize;
    rawdb_.resize(dbsize);
    std::generate(rawdb_.begin(), rawdb_.end(), [n = 0]() mutable {
      ++n;
      return 4 * n + 2600;
    });

    pir_params_ = CreatePIRParameters(rawdb_.size(), dimensions,
                                      GenerateHEParams(poly_modulus_degree));
    pirdb_ = PIRDatabase::Create(rawdb_, pir_params_).ValueOrDie();

    auto encryptionParams =
        GenerateEncryptionParams(pir_params_.he_parameters());
    seal_context_ = seal::SEALContext::Create(encryptionParams);
    if (!seal_context_->parameters_set()) {
      FAIL() << "Error setting encryption parameters: "
             << seal_context_->parameter_error_message();
    }
    keygen_ = make_unique<KeyGenerator>(seal_context_);
    encoder_ = make_unique<seal::IntegerEncoder>(seal_context_);
    encryptor_ = make_unique<Encryptor>(seal_context_, keygen_->public_key());
    evaluator_ = make_unique<Evaluator>(seal_context_);
    decryptor_ = make_unique<Decryptor>(seal_context_, keygen_->secret_key());
  }

  size_t db_size_;
  uint32_t poly_modulus_degree_;
  vector<std::int64_t> rawdb_;
  std::shared_ptr<PIRDatabase> pirdb_;
  PIRParameters pir_params_;
  shared_ptr<SEALContext> seal_context_;
  unique_ptr<seal::IntegerEncoder> encoder_;
  unique_ptr<KeyGenerator> keygen_;
  unique_ptr<Encryptor> encryptor_;
  unique_ptr<Evaluator> evaluator_;
  unique_ptr<Decryptor> decryptor_;
};

TEST_F(PIRDatabaseTest, TestMultiply) {
  vector<int32_t> v(db_size_);
  std::generate(v.begin(), v.end(),
                [n = -db_size_ / 2]() mutable { return n; });
  ASSERT_THAT(pirdb_->size(), Eq(v.size()));

  vector<Ciphertext> cts(v.size());
  int32_t expected = 0;
  for (size_t i = 0; i < cts.size(); ++i) {
    Plaintext pt;
    encoder_->encode(v[i], pt);
    encryptor_->encrypt(pt, cts[i]);
    expected += v[i] * rawdb_[i];
  }

  auto results_or = pirdb_->multiply(cts);
  ASSERT_THAT(results_or.ok(), IsTrue())
      << "Error: " << results_or.status().ToString();
  auto result_ct = results_or.ValueOrDie();

  Plaintext pt;
  decryptor_->decrypt(result_ct, pt);
  auto result = encoder_->decode_int32(pt);

  EXPECT_THAT(result, Eq(expected));
}

TEST_F(PIRDatabaseTest, TestMultiplySelectionVectorTooSmall) {
  SetUpDB(100, 2);
  const uint32_t desired_index = 42;
  const auto dims = PIRDatabase::calculate_dimensions(db_size_, 2);
  const auto indices = PIRDatabase::calculate_indices(dims, desired_index);

  vector<Ciphertext> cts;
  for (size_t d = 0; d < dims.size(); ++d) {
    for (size_t i = 0; i < dims[d]; ++i) {
      Ciphertext ct;
      encryptor_->encrypt_zero(ct);
      cts.push_back(ct);
    }
  }

  cts.resize(cts.size() - 1);
  auto results_or = pirdb_->multiply(cts);
  ASSERT_THAT(results_or.status().code(),
              Eq(private_join_and_compute::StatusCode::kInvalidArgument));
}

TEST_F(PIRDatabaseTest, TestMultiplySelectionVectorTooBig) {
  SetUpDB(100, 2);
  const uint32_t desired_index = 42;
  const auto dims = PIRDatabase::calculate_dimensions(db_size_, 2);
  const auto indices = PIRDatabase::calculate_indices(dims, desired_index);

  vector<Ciphertext> cts;
  for (size_t d = 0; d < dims.size(); ++d) {
    for (size_t i = 0; i < dims[d] + 1; ++i) {
      Ciphertext ct;
      encryptor_->encrypt_zero(ct);
      cts.push_back(ct);
    }
  }

  auto results_or = pirdb_->multiply(cts);
  ASSERT_THAT(results_or.status().code(),
              Eq(private_join_and_compute::StatusCode::kInvalidArgument));
}

class MultiplyMultiDimTest
    : public PIRDatabaseTest,
      public testing::WithParamInterface<
          tuple<uint32_t, uint32_t, uint32_t, uint32_t>> {};

TEST_P(MultiplyMultiDimTest, TestMultiply) {
  const auto poly_modulus_degree = get<0>(GetParam());
  const auto dbsize = get<1>(GetParam());
  const auto d = get<2>(GetParam());
  const auto desired_index = get<3>(GetParam());
  SetUpDB(dbsize, d, poly_modulus_degree);
  const auto dims = PIRDatabase::calculate_dimensions(dbsize, d);
  const auto indices = PIRDatabase::calculate_indices(dims, desired_index);

  vector<Ciphertext> cts;
  for (size_t d = 0; d < dims.size(); ++d) {
    for (size_t i = 0; i < dims[d]; ++i) {
      Ciphertext ct;
      if (i == indices[d]) {
        Plaintext pt(POLY_MODULUS_DEGREE);
        pt.set_zero();
        pt[0] = 1;
        encryptor_->encrypt(pt, ct);
      } else {
        encryptor_->encrypt_zero(ct);
      }
      cts.push_back(ct);
    }
  }

  auto relin_keys = keygen_->relin_keys_local();
  auto results_or = pirdb_->multiply(cts, &relin_keys);
  ASSERT_THAT(results_or.ok(), IsTrue())
      << "Error: " << results_or.status().ToString();
  auto result_ct = results_or.ValueOrDie();

  Plaintext result_pt;
  decryptor_->decrypt(result_ct, result_pt);
  auto result = encoder_->decode_uint64(result_pt);
  EXPECT_THAT(result, Eq(rawdb_[desired_index]));
}

INSTANTIATE_TEST_SUITE_P(
    Multiplies, MultiplyMultiDimTest,
    testing::Values(make_tuple(4096, 10, 1, 7), make_tuple(4096, 16, 2, 11),
                    make_tuple(4096, 16, 2, 0), make_tuple(4096, 16, 2, 15),
                    make_tuple(4096, 82, 2, 42), make_tuple(8192, 27, 3, 2),
                    make_tuple(8192, 117, 3, 17),
                    make_tuple(8192, 222, 4, 111)));

class CalculateIndicesTest
    : public testing::TestWithParam<
          tuple<uint32_t, uint32_t, uint32_t, vector<uint32_t>>> {};

TEST_P(CalculateIndicesTest, IndicesExamples) {
  const auto num_items = get<0>(GetParam());
  const auto d = get<1>(GetParam());
  const auto desired_index = get<2>(GetParam());
  const auto& expected_indices = get<3>(GetParam());
  ASSERT_THAT(expected_indices, SizeIs(d));
  auto dims = PIRDatabase::calculate_dimensions(num_items, d);
  auto indices = PIRDatabase::calculate_indices(dims, desired_index);
  EXPECT_THAT(indices, ContainerEq(expected_indices));
}

INSTANTIATE_TEST_SUITE_P(
    CalculateIndices, CalculateIndicesTest,
    Values(make_tuple(100, 1, 42, vector<uint32_t>{42}),
           make_tuple(100, 1, 7, vector<uint32_t>{7}),
           make_tuple(84, 2, 7, vector<uint32_t>{0, 7}),
           make_tuple(87, 2, 27, vector<uint32_t>{3, 0}),
           make_tuple(87, 2, 42, vector<uint32_t>{4, 6}),
           make_tuple(87, 2, 86, vector<uint32_t>{9, 5}),
           make_tuple(82, 3, 3, vector<uint32_t>{0, 0, 3}),
           make_tuple(82, 3, 20, vector<uint32_t>{1, 0, 0}),
           make_tuple(82, 3, 75, vector<uint32_t>{3, 3, 3})));

class CalculateDimensionsTest
    : public testing::TestWithParam<
          tuple<uint32_t, uint32_t, vector<uint32_t>>> {};

TEST_P(CalculateDimensionsTest, dimensionsExamples) {
  EXPECT_THAT(
      PIRDatabase::calculate_dimensions(get<0>(GetParam()), get<1>(GetParam())),
      ContainerEq(get<2>(GetParam())));
}

INSTANTIATE_TEST_SUITE_P(
    CalculateDimensions, CalculateDimensionsTest,
    testing::Values(make_tuple(100, 1, vector<uint32_t>{100}),
                    make_tuple(100, 2, vector<uint32_t>{10, 10}),
                    make_tuple(82, 2, vector<uint32_t>{10, 9}),
                    make_tuple(975, 2, vector<uint32_t>{32, 31}),
                    make_tuple(1000, 3, vector<uint32_t>{10, 10, 10}),
                    make_tuple(1001, 3, vector<uint32_t>{11, 10, 10}),
                    make_tuple(1000001, 3, vector<uint32_t>{101, 100, 100})));

}  // namespace
}  // namespace pir
