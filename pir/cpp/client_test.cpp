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

#include "client.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "utils.h"

namespace pir {

using seal::Ciphertext;
using seal::Plaintext;
using std::get;
using std::make_tuple;
using std::tuple;
using namespace ::testing;

constexpr uint32_t POLY_MODULUS_DEGREE = 4096;

class PIRClientTest : public ::testing::Test {
 protected:
  void SetUp() { SetUpDB(10); }

  void SetUpDB(size_t dbsize, size_t dimensions = 1) {
    db_size_ = dbsize;
    pir_params_ = PIRParameters::Create(
        dbsize, dimensions, generateEncryptionParams(POLY_MODULUS_DEGREE));
    client_ = PIRClient::Create(pir_params_).ValueOrDie();
    ASSERT_TRUE(client_ != nullptr);
  }

  PIRContext* Context() { return client_->context_.get(); }
  std::shared_ptr<seal::Decryptor> Decryptor() { return client_->decryptor_; }
  std::shared_ptr<seal::Encryptor> Encryptor() { return client_->encryptor_; }

  size_t db_size_;
  std::shared_ptr<PIRParameters> pir_params_;
  std::unique_ptr<PIRClient> client_;
};

TEST_F(PIRClientTest, TestCreateRequest) {
  const size_t desired_index = 5;

  auto payload = client_->CreateRequest(desired_index).ValueOrDie();
  Plaintext pt;
  ASSERT_EQ(payload.Get().size(), 1);
  Decryptor()->decrypt(payload.Get()[0], pt);

  const auto plain_mod =
      pir_params_->GetEncryptionParams().plain_modulus().value();
  EXPECT_EQ((pt[desired_index] * next_power_two(db_size_)) % plain_mod, 1);
  for (size_t i = 0; i < pt.coeff_count(); ++i) {
    if (i != desired_index) {
      EXPECT_EQ(pt[i], 0);
    }
  }
}

TEST_F(PIRClientTest, TestCreateRequestD2) {
  SetUpDB(84, 2);
  const size_t desired_index = 42;
  const size_t num_rows = 10;
  const size_t num_cols = 9;
  const size_t total_s_items = num_rows + num_cols;
  ASSERT_THAT(Context()->Parameters()->Dimensions(),
              ElementsAre(num_rows, num_cols));

  auto payload = client_->CreateRequest(desired_index).ValueOrDie();
  Plaintext pt;
  ASSERT_EQ(payload.Get().size(), 1);
  Decryptor()->decrypt(payload.Get()[0], pt);

  const size_t expected_row = 4;
  const size_t expected_col = 6;
  const auto plain_mod =
      pir_params_->GetEncryptionParams().plain_modulus().value();
  // NB: both row and column selection vectors are packed into the same CT
  EXPECT_EQ((pt[expected_row] * next_power_two(total_s_items)) % plain_mod, 1);
  EXPECT_EQ(
      (pt[num_rows + expected_col] * next_power_two(total_s_items)) % plain_mod,
      1);
  for (size_t i = 0; i < pt.coeff_count(); ++i) {
    if (i != expected_row && i != (num_rows + expected_col)) {
      EXPECT_EQ(pt[i], 0) << "i = " << i;
    }
  }
}

TEST_F(PIRClientTest, TestCreateRequestD3) {
  SetUpDB(82, 3);
  const size_t desired_index = 42;
  const size_t num_rows = 5;
  const size_t num_cols = 5;
  const size_t num_depth = 4;
  const size_t total_s_items = num_rows + num_cols + num_depth;
  ASSERT_THAT(Context()->Parameters()->Dimensions(),
              ElementsAre(num_rows, num_cols, num_depth));

  auto payload = client_->CreateRequest(desired_index).ValueOrDie();
  Plaintext pt;
  ASSERT_EQ(payload.Get().size(), 1);
  Decryptor()->decrypt(payload.Get()[0], pt);

  const size_t expected_row = 2;
  const size_t expected_col = 0;
  const size_t expected_depth = 2;
  const auto plain_mod =
      pir_params_->GetEncryptionParams().plain_modulus().value();
  EXPECT_EQ((pt[expected_row] * next_power_two(total_s_items)) % plain_mod, 1);
  EXPECT_EQ(
      (pt[num_rows + expected_col] * next_power_two(total_s_items)) % plain_mod,
      1);
  EXPECT_EQ((pt[num_rows + num_cols + expected_depth] *
             next_power_two(total_s_items)) %
                plain_mod,
            1);
  for (size_t i = 0; i < pt.coeff_count(); ++i) {
    if (i != expected_row && i != (num_rows + expected_col) &&
        i != (num_rows + num_cols + expected_depth)) {
      EXPECT_EQ(pt[i], 0) << "i = " << i;
    }
  }
}

TEST_F(PIRClientTest, TestCreateRequestMultiDimMultiCT1) {
  SetUpDB(20000000, 2);
  const size_t desired_index = 12345679;
  const size_t num_rows = 4473;
  const size_t num_cols = 4472;
  ASSERT_THAT(Context()->Parameters()->Dimensions(),
              ElementsAre(num_rows, num_cols));

  auto payload = client_->CreateRequest(desired_index).ValueOrDie();
  ASSERT_EQ(payload.Get().size(), 3);

  const size_t expected_row = 2760;
  const size_t expected_col = 2959;
  const auto plain_mod =
      pir_params_->GetEncryptionParams().plain_modulus().value();

  vector<Plaintext> pts(payload.Get().size());
  for (size_t i = 0; i < pts.size(); ++i) {
    Decryptor()->decrypt(payload.Get()[i], pts[i]);
  }

  // first plaintext should be all zero except for row value
  EXPECT_EQ((pts[0][expected_row] * POLY_MODULUS_DEGREE) % plain_mod, 1);
  for (size_t i = 0; i < pts[0].coeff_count(); ++i) {
    if (i != expected_row) {
      EXPECT_EQ(pts[0][i], 0) << "i = " << i;
    }
  }

  // second plaintext should be all zero except for col value with offset from
  // values for row value
  const size_t expected_index = expected_col + num_rows - POLY_MODULUS_DEGREE;
  EXPECT_EQ((pts[1][expected_index] * POLY_MODULUS_DEGREE) % plain_mod, 1);
  for (size_t i = 0; i < pts[1].coeff_count(); ++i) {
    if (i != expected_index) {
      EXPECT_EQ(pts[1][i], 0) << "i = " << i;
    }
  }

  // third plaintext should be all zeros
  for (size_t i = 0; i < pts[2].coeff_count(); ++i) {
    EXPECT_EQ(pts[2][i], 0) << "i = " << i;
  }
}

TEST_F(PIRClientTest, TestCreateRequestMultiDimMultiCT2) {
  SetUpDB(20000000, 2);
  const size_t desired_index = 12346679;
  const size_t num_rows = 4473;
  const size_t num_cols = 4472;
  ASSERT_THAT(Context()->Parameters()->Dimensions(),
              ElementsAre(num_rows, num_cols));

  auto payload = client_->CreateRequest(desired_index).ValueOrDie();
  ASSERT_EQ(payload.Get().size(), 3);

  const size_t expected_row = 2760;
  const size_t expected_col = 3959;
  const auto plain_mod =
      pir_params_->GetEncryptionParams().plain_modulus().value();

  vector<Plaintext> pts(payload.Get().size());
  for (size_t i = 0; i < pts.size(); ++i) {
    Decryptor()->decrypt(payload.Get()[i], pts[i]);
  }

  // first plaintext should be all zero except for row value
  EXPECT_EQ((pts[0][expected_row] * POLY_MODULUS_DEGREE) % plain_mod, 1);
  for (size_t i = 0; i < pts[0].coeff_count(); ++i) {
    if (i != expected_row) {
      EXPECT_EQ(pts[0][i], 0) << "i = " << i;
    }
  }

  // second plaintext should be all zeros
  for (size_t i = 0; i < pts[1].coeff_count(); ++i) {
    EXPECT_EQ(pts[1][i], 0) << "i = " << i;
  }
  // third plaintext should be all zero except for col value with offset
  const size_t expected_index =
      expected_col + num_rows - 2 * POLY_MODULUS_DEGREE;
  const size_t m = next_power_two((num_rows + num_cols) % POLY_MODULUS_DEGREE);
  EXPECT_EQ((pts[2][expected_index] * m) % plain_mod, 1);
  for (size_t i = 0; i < pts[2].coeff_count(); ++i) {
    if (i != expected_index) {
      EXPECT_EQ(pts[2][i], 0) << "i = " << i;
    }
  }
}

TEST_F(PIRClientTest, TestProcessResponse) {
  int64_t value = 987654321;

  // Create a fake payload.
  Plaintext pt;
  Context()->Encoder()->encode(value, pt);
  vector<Ciphertext> ct(1);
  Encryptor()->encrypt(pt, ct[0]);
  PIRPayload payload = PIRPayload::Load(ct);

  auto result = client_->ProcessResponse(payload).ValueOrDie();
  ASSERT_EQ(result, value);
}

TEST_F(PIRClientTest, TestCreateRequest_InvalidIndex) {
  auto payload_or = client_->CreateRequest(db_size_ + 1);
  ASSERT_EQ(payload_or.status().code(),
            private_join_and_compute::StatusCode::kInvalidArgument);
}

class CreateRequestTest
    : public PIRClientTest,
      public testing::WithParamInterface<tuple<size_t, size_t, uint64_t>> {};

TEST_P(CreateRequestTest, TestCreateRequest_MoreThanOneCT) {
  const auto dbsize = get<0>(GetParam());
  int desired_index = get<1>(GetParam());
  SetUpDB(dbsize);

  const auto poly_modulus_degree =
      pir_params_->GetEncryptionParams().poly_modulus_degree();
  const auto plain_mod =
      pir_params_->GetEncryptionParams().plain_modulus().value();

  auto payload_or = client_->CreateRequest(desired_index);
  ASSERT_TRUE(payload_or.ok())
      << "Status is: " << payload_or.status().ToString();
  auto payload = payload_or.ValueOrDie();
  ASSERT_EQ(payload.Get().size(), dbsize / poly_modulus_degree + 1);

  for (const auto& ct : payload.Get()) {
    Plaintext pt;
    Decryptor()->decrypt(ct, pt);
    for (size_t i = 0; i < pt.coeff_count(); ++i) {
      if (i != static_cast<size_t>(desired_index)) {
        EXPECT_EQ(pt[i], 0);
      }
    }
    if (desired_index < 0 ||
        static_cast<size_t>(desired_index) >= poly_modulus_degree) {
      desired_index -= poly_modulus_degree;
      for (size_t i = 0; i < pt.coeff_count(); ++i) {
        EXPECT_EQ(pt[i], 0);
      }
    } else {
      auto m = get<2>(GetParam());
      EXPECT_EQ((pt[desired_index] * m) % plain_mod, 1);
      desired_index = -1;
    }
  }
}

INSTANTIATE_TEST_SUITE_P(
    Requests, CreateRequestTest,
    testing::Values(
        make_tuple(10000, 5005, POLY_MODULUS_DEGREE),
        make_tuple(10000, 0, POLY_MODULUS_DEGREE),
        make_tuple(10000, 1, POLY_MODULUS_DEGREE),
        make_tuple(10000, 3333, POLY_MODULUS_DEGREE),
        make_tuple(10000, 4095, POLY_MODULUS_DEGREE),
        make_tuple(10000, 4096, POLY_MODULUS_DEGREE),
        make_tuple(10000, 4097, POLY_MODULUS_DEGREE),
        make_tuple(10000, 8191, POLY_MODULUS_DEGREE),
        make_tuple(10000, 8192, 2048), make_tuple(10000, 8193, 2048),
        make_tuple(10000, 9007, 2048), make_tuple(10000, 9999, 2048),
        make_tuple(4096, 0, 4096), make_tuple(4096, 4095, 4096),
        make_tuple(16384, 12288, 4096), make_tuple(16384, 12289, 4096),
        make_tuple(16384, 16383, 4096)));

class CalculateIndicesTest
    : public PIRClientTest,
      public testing::WithParamInterface<
          tuple<uint32_t, uint32_t, uint32_t, vector<uint32_t>>> {};

TEST_P(CalculateIndicesTest, IndicesExamples) {
  const auto num_items = get<0>(GetParam());
  const auto d = get<1>(GetParam());
  const auto desired_index = get<2>(GetParam());
  const auto& expected_indices = get<3>(GetParam());
  ASSERT_THAT(expected_indices, SizeIs(d));
  SetUpDB(num_items, d);
  ASSERT_THAT(Context()->Parameters()->Dimensions(),
              ContainerEq(PIRParameters::calculate_dimensions(num_items, d)));
  auto indices = client_->calculate_indices(desired_index);
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

}  // namespace pir
