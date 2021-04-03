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
#include "pir/cpp/ct_reencoder.h"
#include "pir/cpp/server.h"
#include "pir/cpp/status_asserts.h"
#include "pir/cpp/string_encoder.h"
#include "pir/cpp/test_base.h"
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

class PIRDatabaseTestBase : public PIRTestingBase {
 protected:
  void SetUpDBImpl(size_t dbsize, size_t dimensions,
                   uint32_t poly_modulus_degree, uint32_t plain_mod_bit_size,
                   bool use_ciphertext_multiplication) {
    SetUpParams(dbsize, 0, dimensions, poly_modulus_degree, plain_mod_bit_size,
                0, use_ciphertext_multiplication);
    GenerateIntDB();
    SetUpSealTools();
    encoder_ = make_unique<seal::IntegerEncoder>(seal_context_);
  }

  void SetUpStringDBImpl(size_t dbsize, size_t dimensions = 1,
                         uint32_t poly_modulus_degree = POLY_MODULUS_DEGREE,
                         uint32_t plain_mod_bit_size = 20, size_t elem_size = 0,
                         bool use_ciphertext_multiplication = false) {
    SetUpParams(dbsize, elem_size, dimensions, poly_modulus_degree,
                plain_mod_bit_size, 0, use_ciphertext_multiplication);
    GenerateDB();
    SetUpSealTools();
  }

  void decode_result(vector<Ciphertext> result_cts, Plaintext& result_pt,
                     size_t input_ct_size, size_t d,
                     bool use_ciphertext_multiplication) {
    if (use_ciphertext_multiplication) {
      ASSERT_EQ(result_cts.size(), 1);
      decryptor_->decrypt(result_cts[0], result_pt);
    } else {
      decode_from_decomp(result_cts, result_pt, input_ct_size, d);
    }
  }
  void decode_from_decomp(vector<Ciphertext> result_cts, Plaintext& result_pt,
                          size_t input_ct_size, size_t d) {
    ASSERT_GT(d, 0);
    if (d <= 1) {
      ASSERT_EQ(result_cts.size(), 1);
      decryptor_->decrypt(result_cts[0], result_pt);
      return;
    }

    ASSIGN_OR_FAIL(auto ct_reencoder,
                   CiphertextReencoder::Create(seal_context_));
    ASSERT_EQ(result_cts.size(),
              ipow(ct_reencoder->ExpansionRatio() * input_ct_size, d - 1));

    auto result_pts =
        decode_recursion(result_cts, input_ct_size, d, ct_reencoder.get());
    ASSERT_EQ(result_pts.size(), 1);
    result_pt = result_pts[0];
  }

  vector<Plaintext> decode_recursion(vector<Ciphertext> cts,
                                     size_t input_ct_size, size_t d,
                                     CiphertextReencoder* ct_reencoder) {
    vector<Plaintext> pts(cts.size());
    for (size_t i = 0; i < pts.size(); ++i) {
      decryptor_->decrypt(cts[i], pts[i]);
    }

    if (d <= 1) {
      return pts;
    }

    size_t expansion_ratio = ct_reencoder->ExpansionRatio() * input_ct_size;
    vector<Ciphertext> result_cts(cts.size() / expansion_ratio);
    for (size_t i = 0; i < result_cts.size(); ++i) {
      result_cts[i] = ct_reencoder->Decode(pts.begin() + (i * expansion_ratio),
                                           input_ct_size);
    }
    return decode_recursion(result_cts, input_ct_size, d - 1, ct_reencoder);
  }

  unique_ptr<seal::IntegerEncoder> encoder_;
};

class PIRDatabaseTest : public PIRDatabaseTestBase,
                        public ::testing::TestWithParam<bool> {
 protected:
  void SetUp() { SetUpDB(100); }

  void SetUpDB(size_t dbsize, size_t dimensions = 1,
               uint32_t poly_modulus_degree = POLY_MODULUS_DEGREE,
               uint32_t plain_mod_bit_size = 20) {
    bool use_ciphertext_multiplication = GetParam();
    SetUpDBImpl(dbsize, dimensions, poly_modulus_degree, plain_mod_bit_size,
                use_ciphertext_multiplication);
  }

  void SetUpStringDB(size_t dbsize, size_t dimensions = 1,
                     uint32_t poly_modulus_degree = POLY_MODULUS_DEGREE,
                     uint32_t plain_mod_bit_size = 20, size_t elem_size = 0) {
    bool use_ciphertext_multiplication = GetParam();
    SetUpStringDBImpl(dbsize, dimensions, poly_modulus_degree,
                      plain_mod_bit_size, elem_size,
                      use_ciphertext_multiplication);
  }
};

TEST_P(PIRDatabaseTest, TestMultiply) {
  vector<int32_t> v(db_size_);
  std::generate(v.begin(), v.end(),
                [n = -db_size_ / 2]() mutable { return n; });
  ASSERT_THAT(pir_db_->size(), Eq(v.size()));

  vector<Ciphertext> cts(v.size());
  int64_t expected = 0;
  for (size_t i = 0; i < cts.size(); ++i) {
    Plaintext pt;
    encoder_->encode(v[i], pt);
    encryptor_->encrypt(pt, cts[i]);
    expected += v[i] * int_db_[i];
  }

  ASSIGN_OR_FAIL(auto result_cts, pir_db_->multiply(cts, nullptr));
  ASSERT_EQ(result_cts.size(), 1);

  Plaintext pt;
  decryptor_->decrypt(result_cts[0], pt);
  auto result = encoder_->decode_int64(pt);

  EXPECT_THAT(result, Eq(expected));
}

TEST_P(PIRDatabaseTest, TestMultiplySelectionVectorTooSmall) {
  SetUpDB(100, 2);
  const uint32_t desired_index = 42;
  const auto dims = PIRDatabase::calculate_dimensions(db_size_, 2);
  const auto indices = pir_db_->calculate_indices(desired_index);

  vector<Ciphertext> cts;
  for (size_t d = 0; d < dims.size(); ++d) {
    for (size_t i = 0; i < dims[d]; ++i) {
      Ciphertext ct;
      encryptor_->encrypt_zero(ct);
      cts.push_back(ct);
    }
  }

  cts.resize(cts.size() - 1);
  auto results_or = pir_db_->multiply(cts);
  ASSERT_THAT(results_or.status().code(),
              Eq(absl::StatusCode::kInvalidArgument));
}

TEST_P(PIRDatabaseTest, TestMultiplySelectionVectorTooBig) {
  SetUpDB(100, 2);
  const uint32_t desired_index = 42;
  const auto dims = PIRDatabase::calculate_dimensions(db_size_, 2);
  const auto indices = pir_db_->calculate_indices(desired_index);

  vector<Ciphertext> cts;
  for (size_t d = 0; d < dims.size(); ++d) {
    for (size_t i = 0; i < dims[d] + 1; ++i) {
      Ciphertext ct;
      encryptor_->encrypt_zero(ct);
      cts.push_back(ct);
    }
  }

  auto results_or = pir_db_->multiply(cts);
  ASSERT_THAT(results_or.status().code(),
              Eq(absl::StatusCode::kInvalidArgument));
}

TEST_P(PIRDatabaseTest, TestMultiplyStringValues) {
  constexpr size_t db_size = 10;
  constexpr size_t desired_index = 7;

  SetUpStringDB(db_size, 1, POLY_MODULUS_DEGREE, 22);

  vector<Plaintext> selection_vector_pt(db_size);
  vector<Ciphertext> selection_vector_ct(db_size);
  for (size_t i = 0; i < db_size; ++i) {
    selection_vector_pt[i].resize(POLY_MODULUS_DEGREE);
    selection_vector_pt[i].set_zero();
    if (i == desired_index) {
      selection_vector_pt[i][0] = 1;
    }
    encryptor_->encrypt(selection_vector_pt[i], selection_vector_ct[i]);
  }

  ASSIGN_OR_FAIL(auto result_cts, pir_db_->multiply(selection_vector_ct));
  ASSERT_EQ(result_cts.size(), 1);

  Plaintext result_pt;
  decryptor_->decrypt(result_cts[0], result_pt);
  auto string_encoder = make_unique<StringEncoder>(seal_context_);
  ASSIGN_OR_FAIL(auto result, string_encoder->decode(result_pt));

  EXPECT_THAT(result, Eq(string_db_[desired_index]));
}

vector<Ciphertext> create_selection_vector(const vector<uint32_t>& dims,
                                           const vector<uint32_t>& indices,
                                           Encryptor& encryptor) {
  vector<Ciphertext> cts;
  for (size_t d = 0; d < dims.size(); ++d) {
    for (size_t i = 0; i < dims[d]; ++i) {
      Ciphertext ct;
      if (i == indices[d]) {
        Plaintext pt(POLY_MODULUS_DEGREE);
        pt.set_zero();
        pt[0] = 1;
        encryptor.encrypt(pt, ct);
      } else {
        encryptor.encrypt_zero(ct);
      }
      cts.push_back(ct);
    }
  }
  return cts;
}

TEST_P(PIRDatabaseTest, TestMultiplyStringValuesD2) {
  constexpr size_t d = 2;
  constexpr size_t db_size = 9;
  constexpr size_t desired_index = 5;

  SetUpStringDB(db_size, d, POLY_MODULUS_DEGREE, 16);

  const auto dims = PIRDatabase::calculate_dimensions(db_size, d);
  const auto indices = pir_db_->calculate_indices(desired_index);
  auto sv = create_selection_vector(dims, indices, *encryptor_);

  auto relin_keys = keygen_->relin_keys_local();
  ASSIGN_OR_FAIL(auto result_cts, pir_db_->multiply(sv, &relin_keys));
  Plaintext result_pt;
  decode_result(result_cts, result_pt, sv[0].size(), d, GetParam());

  auto string_encoder = make_unique<StringEncoder>(seal_context_);
  ASSIGN_OR_FAIL(auto result, string_encoder->decode(result_pt));

  EXPECT_THAT(result.substr(0, string_db_[desired_index].size()),
              Eq(string_db_[desired_index]));
}

TEST_P(PIRDatabaseTest, TestMultiplyMultipleValuesPerPT) {
  constexpr size_t d = 2;
  constexpr size_t db_size = 1000;
  constexpr size_t elem_size = 128;
  constexpr size_t desired_index = 754;

  SetUpStringDB(db_size, d, POLY_MODULUS_DEGREE, 16, elem_size);
  ASSERT_EQ(pir_db_->size(), pir_params_->num_pt());
  ASSERT_EQ(pir_params_->bytes_per_item(), elem_size);

  const size_t items_per_pt = pir_params_->items_per_plaintext();
  const size_t num_db_pt = ceil(static_cast<double>(db_size) / items_per_pt);
  const size_t desired_pt_index = desired_index / items_per_pt;
  const size_t desired_offset =
      (desired_index - desired_pt_index * items_per_pt) * elem_size;

  const auto dims = PIRDatabase::calculate_dimensions(num_db_pt, d);
  const auto indices = pir_db_->calculate_indices(desired_index);
  auto sv = create_selection_vector(dims, indices, *encryptor_);

  auto relin_keys = keygen_->relin_keys_local();
  ASSIGN_OR_FAIL(auto result_cts, pir_db_->multiply(sv, &relin_keys));

  Plaintext result_pt;
  decode_result(result_cts, result_pt, sv[0].size(), d, GetParam());
  auto string_encoder = make_unique<StringEncoder>(seal_context_);
  ASSIGN_OR_FAIL(auto result,
                 string_encoder->decode(result_pt, elem_size, desired_offset));

  EXPECT_THAT(result, Eq(string_db_[desired_index]));
}

TEST_P(PIRDatabaseTest, TestCreateValueDoesntMatch) {
  SetUpParams(10, 9728, 1, 4096, 20, 19);

  auto prng =
      seal::UniformRandomGeneratorFactory::DefaultFactory()->create({42});
  vector<string> db(db_size_);
  for (size_t i = 0; i < db_size_; ++i) {
    db[i].resize(9729);
    prng->generate(db[i].size(), reinterpret_cast<SEAL_BYTE*>(db[i].data()));
  }

  auto pir_db_or = PIRDatabase::Create(db, pir_params_);
  ASSERT_FALSE(pir_db_or.ok());
  ASSERT_EQ(pir_db_or.status().code(), absl::StatusCode::kInvalidArgument);
}

INSTANTIATE_TEST_SUITE_P(PIRDatabaseTests, PIRDatabaseTest,
                         testing::Values(false, true));

class MultiplyMultiDimTest
    : public PIRDatabaseTestBase,
      public testing::TestWithParam<
          tuple<uint32_t, uint32_t, uint32_t, uint32_t, uint32_t>> {
 protected:
  void TestMultiply(bool use_ciphertext_multiplication) {
    const auto poly_modulus_degree = get<0>(GetParam());
    const auto plain_mod_bits = get<1>(GetParam());
    const auto dbsize = get<2>(GetParam());
    const auto d = get<3>(GetParam());
    const auto desired_index = get<4>(GetParam());
    SetUpStringDBImpl(dbsize, d, poly_modulus_degree, plain_mod_bits, 0,
                      use_ciphertext_multiplication);
    const size_t elem_size = pir_params_->bytes_per_item();
    const auto dims = PIRDatabase::calculate_dimensions(dbsize, d);
    const auto indices = pir_db_->calculate_indices(desired_index);
    auto cts = create_selection_vector(dims, indices, *encryptor_);

    unique_ptr<RelinKeys> relin_keys;
    if (use_ciphertext_multiplication) {
      relin_keys = make_unique<RelinKeys>(keygen_->relin_keys_local());
    }
    ASSIGN_OR_FAIL(auto result_cts, pir_db_->multiply(cts, relin_keys.get()));

    Plaintext result_pt;
    decode_result(result_cts, result_pt, cts[0].size(), d,
                  use_ciphertext_multiplication);
    auto string_encoder = make_unique<StringEncoder>(seal_context_);
    ASSIGN_OR_FAIL(auto result, string_encoder->decode(result_pt, elem_size));
    EXPECT_THAT(result, Eq(string_db_[desired_index]));
  }
};

TEST_P(MultiplyMultiDimTest, CTDecomp) { TestMultiply(false); }

TEST_P(MultiplyMultiDimTest, CTMultiply) { TestMultiply(true); }

INSTANTIATE_TEST_SUITE_P(PIRDatabaseMultiplies, MultiplyMultiDimTest,
                         testing::Values(make_tuple(4096, 16, 10, 1, 7),
                                         make_tuple(4096, 16, 16, 2, 11),
                                         make_tuple(4096, 16, 16, 2, 0),
                                         make_tuple(4096, 16, 16, 2, 15),
                                         make_tuple(4096, 16, 82, 2, 42),
                                         make_tuple(8192, 20, 27, 3, 2),
                                         make_tuple(8192, 20, 117, 3, 17)));

class CalculateIndicesTest
    : public testing::TestWithParam<
          tuple<uint32_t, uint32_t, uint32_t, uint32_t, vector<uint32_t>>> {};

TEST_P(CalculateIndicesTest, IndicesExamples) {
  const auto num_items = get<0>(GetParam());
  const auto size_per_item = get<1>(GetParam());
  const auto d = get<2>(GetParam());
  const auto desired_index = get<3>(GetParam());
  const auto& expected_indices = get<4>(GetParam());
  ASSIGN_OR_FAIL(const auto pir_params,
                 CreatePIRParameters(num_items, size_per_item, d,
                                     GenerateEncryptionParams(4096, 16)));
  ASSIGN_OR_FAIL(auto pir_db, PIRDatabase::Create(pir_params));
  ASSERT_THAT(expected_indices, SizeIs(d));
  auto indices = pir_db->calculate_indices(desired_index);
  EXPECT_THAT(indices, ContainerEq(expected_indices));
}

INSTANTIATE_TEST_SUITE_P(
    PIRDatabaseCalculateIndices, CalculateIndicesTest,
    Values(make_tuple(100, 0, 1, 42, vector<uint32_t>{42}),
           make_tuple(100, 0, 1, 7, vector<uint32_t>{7}),
           make_tuple(84, 0, 2, 7, vector<uint32_t>{0, 7}),
           make_tuple(87, 0, 2, 27, vector<uint32_t>{3, 0}),
           make_tuple(87, 0, 2, 42, vector<uint32_t>{4, 6}),
           make_tuple(87, 0, 2, 86, vector<uint32_t>{9, 5}),
           make_tuple(82, 0, 3, 3, vector<uint32_t>{0, 0, 3}),
           make_tuple(82, 0, 3, 20, vector<uint32_t>{1, 0, 0}),
           make_tuple(82, 0, 3, 75, vector<uint32_t>{3, 3, 3}),
           make_tuple(5000, 64, 1, 2222, vector<uint32_t>{18}),
           make_tuple(5000, 64, 1, 1200, vector<uint32_t>{10})));

class CalculateOffsetTest : public testing::TestWithParam<
                                tuple<uint32_t, uint32_t, uint32_t, uint32_t>> {
};

TEST_P(CalculateOffsetTest, OffsetExamples) {
  const auto num_items = get<0>(GetParam());
  const auto size_per_item = get<1>(GetParam());
  const auto desired_index = get<2>(GetParam());
  const auto& expected_offset = get<3>(GetParam());
  ASSIGN_OR_FAIL(const auto pir_params,
                 CreatePIRParameters(num_items, size_per_item, 1,
                                     GenerateEncryptionParams(4096, 16)));
  ASSIGN_OR_FAIL(auto pir_db, PIRDatabase::Create(pir_params));
  auto offset = pir_db->calculate_item_offset(desired_index);
  EXPECT_EQ(offset, expected_offset);
}

INSTANTIATE_TEST_SUITE_P(PIRDatabaseCalculateOffset, CalculateOffsetTest,
                         Values(make_tuple(100, 0, 42, 0),
                                make_tuple(1000, 64, 42, 2688),
                                make_tuple(1000, 64, 960, 0),
                                make_tuple(1000, 64, 999, 2496)));

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
