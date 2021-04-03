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

#include "pir/cpp/client.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "pir/cpp/ct_reencoder.h"
#include "pir/cpp/server.h"
#include "pir/cpp/status_asserts.h"
#include "pir/cpp/string_encoder.h"
#include "pir/cpp/utils.h"

namespace pir {

using namespace seal;
using std::get;
using std::make_tuple;
using std::make_unique;
using std::shared_ptr;
using std::tuple;
using std::unique_ptr;
using std::vector;
using namespace ::testing;

constexpr uint32_t POLY_MODULUS_DEGREE = 4096;

class PIRClientTest : public ::testing::Test {
 protected:
  void SetUp() { SetUpDB(100); }

  void SetUpDB(size_t dbsize, size_t dimensions = 1, size_t elem_size = 0,
               bool use_ciphertext_multiplication = false) {
    db_size_ = dbsize;
    encryption_params_ = GenerateEncryptionParams(POLY_MODULUS_DEGREE, 16);
    pir_params_ =
        *(CreatePIRParameters(dbsize, elem_size, dimensions, encryption_params_,
                              use_ciphertext_multiplication));
    client_ = *(PIRClient::Create(pir_params_));

    ASSERT_TRUE(client_ != nullptr);
  }

  const auto& Context() { return client_->context_; }
  std::shared_ptr<seal::Decryptor> Decryptor() { return client_->decryptor_; }
  std::shared_ptr<seal::Encryptor> Encryptor() { return client_->encryptor_; }

  size_t db_size_;
  shared_ptr<PIRParameters> pir_params_;
  EncryptionParameters encryption_params_;
  std::unique_ptr<PIRClient> client_;
};

TEST_F(PIRClientTest, TestCreateRequest) {
  const size_t desired_index = 5;
  const vector<size_t> indices = {desired_index};

  ASSIGN_OR_FAIL(auto req_proto, client_->CreateRequest(indices));
  ASSERT_EQ(req_proto.query_size(), 1);
  ASSIGN_OR_FAIL(auto req,
                 LoadCiphertexts(Context()->SEALContext(), req_proto.query(0)));

  Plaintext pt;
  ASSERT_EQ(req.size(), 1);
  EXPECT_THAT(req_proto.galois_keys(), Not(IsEmpty()));
  Decryptor()->decrypt(req[0], pt);

  const auto plain_mod = encryption_params_.plain_modulus().value();
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
  const vector<size_t> indices = {desired_index};

  const size_t num_rows = 10;
  const size_t num_cols = 9;
  const size_t total_s_items = num_rows + num_cols;
  ASSERT_THAT(Context()->Params()->dimensions(),
              ElementsAre(num_rows, num_cols));

  ASSIGN_OR_FAIL(auto request_proto, client_->CreateRequest(indices));
  ASSERT_EQ(request_proto.query_size(), 1);
  ASSIGN_OR_FAIL(auto request, LoadCiphertexts(Context()->SEALContext(),
                                               request_proto.query(0)));
  Plaintext pt;
  ASSERT_EQ(request.size(), 1);
  EXPECT_THAT(request_proto.galois_keys(), Not(IsEmpty()));
  EXPECT_THAT(request_proto.relin_keys(), Not(IsEmpty()));

  Decryptor()->decrypt(request[0], pt);

  const size_t expected_row = 4;
  const size_t expected_col = 6;
  const auto plain_mod = encryption_params_.plain_modulus().value();
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
  const vector<size_t> indices = {desired_index};

  const size_t num_rows = 5;
  const size_t num_cols = 5;
  const size_t num_depth = 4;
  const size_t total_s_items = num_rows + num_cols + num_depth;
  ASSERT_THAT(Context()->Params()->dimensions(),
              ElementsAre(num_rows, num_cols, num_depth));

  ASSIGN_OR_FAIL(auto request_proto, client_->CreateRequest(indices));
  ASSERT_EQ(request_proto.query_size(), 1);
  ASSIGN_OR_FAIL(auto request, LoadCiphertexts(Context()->SEALContext(),
                                               request_proto.query(0)));
  Plaintext pt;
  ASSERT_EQ(request.size(), 1);
  EXPECT_THAT(request_proto.galois_keys(), Not(IsEmpty()));
  EXPECT_THAT(request_proto.relin_keys(), Not(IsEmpty()));
  Decryptor()->decrypt(request[0], pt);

  const size_t expected_row = 2;
  const size_t expected_col = 0;
  const size_t expected_depth = 2;
  const auto plain_mod = encryption_params_.plain_modulus().value();
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
  const vector<size_t> indices = {desired_index};
  const size_t num_rows = 4473;
  const size_t num_cols = 4472;
  ASSERT_THAT(Context()->Params()->dimensions(),
              ElementsAre(num_rows, num_cols));

  ASSIGN_OR_FAIL(auto request_proto, client_->CreateRequest(indices));
  ASSERT_EQ(request_proto.query_size(), 1);
  ASSIGN_OR_FAIL(auto request, LoadCiphertexts(Context()->SEALContext(),
                                               request_proto.query(0)));
  ASSERT_EQ(request.size(), 3);
  EXPECT_THAT(request_proto.galois_keys(), Not(IsEmpty()));
  EXPECT_THAT(request_proto.relin_keys(), Not(IsEmpty()));

  const size_t expected_row = 2760;
  const size_t expected_col = 2959;
  const auto plain_mod = encryption_params_.plain_modulus().value();

  vector<Plaintext> pts(request.size());
  for (size_t i = 0; i < pts.size(); ++i) {
    Decryptor()->decrypt(request[i], pts[i]);
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
  const vector<size_t> indices = {desired_index};
  const size_t num_rows = 4473;
  const size_t num_cols = 4472;
  ASSERT_THAT(Context()->Params()->dimensions(),
              ElementsAre(num_rows, num_cols));

  ASSIGN_OR_FAIL(auto request_proto, client_->CreateRequest(indices));
  ASSERT_EQ(request_proto.query_size(), 1);
  ASSIGN_OR_FAIL(auto request, LoadCiphertexts(Context()->SEALContext(),
                                               request_proto.query(0)));
  ASSERT_EQ(request.size(), 3);
  EXPECT_THAT(request_proto.galois_keys(), Not(IsEmpty()));
  EXPECT_THAT(request_proto.relin_keys(), Not(IsEmpty()));

  const size_t expected_row = 2760;
  const size_t expected_col = 3959;
  const auto plain_mod = encryption_params_.plain_modulus().value();

  vector<Plaintext> pts(request.size());
  for (size_t i = 0; i < pts.size(); ++i) {
    Decryptor()->decrypt(request[i], pts[i]);
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

TEST_F(PIRClientTest, TestCreateRequest_InvalidIndex) {
  auto request_or = client_->CreateRequest({db_size_ + 1});
  ASSERT_EQ(request_or.status().code(), absl::StatusCode::kInvalidArgument);
}

class CreateRequestTest : public PIRClientTest,
                          public testing::WithParamInterface<
                              tuple<size_t, vector<size_t>, uint64_t>> {};

TEST_P(CreateRequestTest, TestCreateRequest) {
  const auto dbsize = get<0>(GetParam());
  vector<size_t> indices = get<1>(GetParam());
  SetUpDB(dbsize);

  const auto poly_modulus_degree = encryption_params_.poly_modulus_degree();
  const auto plain_mod = encryption_params_.plain_modulus().value();

  ASSIGN_OR_FAIL(auto request, client_->CreateRequest(indices));
  ASSERT_EQ(request.query_size(), indices.size());
  EXPECT_THAT(request.galois_keys(), Not(IsEmpty()));

  auto m = get<2>(GetParam());

  for (size_t idx = 0; idx < indices.size(); ++idx) {
    ASSIGN_OR_FAIL(auto query, LoadCiphertexts(Context()->SEALContext(),
                                               request.query(idx)));
    ASSERT_EQ(query.size(), dbsize / poly_modulus_degree + 1);
    size_t desired_index = indices[idx];

    for (const auto& ct : query) {
      Plaintext pt;
      Decryptor()->decrypt(ct, pt);

      if (desired_index < 0 ||
          static_cast<size_t>(desired_index) >= poly_modulus_degree) {
        desired_index -= poly_modulus_degree;
        for (size_t i = 0; i < pt.coeff_count(); ++i) {
          EXPECT_EQ(pt[i], 0);
        }
      } else {
        EXPECT_EQ((pt[desired_index] * m) % plain_mod, 1);
        for (size_t i = 0; i < pt.coeff_count(); ++i) {
          if (i != desired_index) {
            EXPECT_EQ(pt[i], 0);
          }
        }
        desired_index = -1;
      }
    }
  }
}

INSTANTIATE_TEST_SUITE_P(
    Requests, CreateRequestTest,
    testing::Values(
        make_tuple(10000, vector<size_t>({5005}), POLY_MODULUS_DEGREE),
        make_tuple(10000, vector<size_t>({0}), POLY_MODULUS_DEGREE),
        make_tuple(10000, vector<size_t>({1}), POLY_MODULUS_DEGREE),
        make_tuple(10000, vector<size_t>({3333}), POLY_MODULUS_DEGREE),
        make_tuple(10000, vector<size_t>({4095}), POLY_MODULUS_DEGREE),
        make_tuple(10000, vector<size_t>({4096}), POLY_MODULUS_DEGREE),
        make_tuple(10000, vector<size_t>({4097}), POLY_MODULUS_DEGREE),
        make_tuple(10000, vector<size_t>({8191}), POLY_MODULUS_DEGREE),
        make_tuple(10000, vector<size_t>({8192}), 2048),
        make_tuple(10000, vector<size_t>({8193}), 2048),
        make_tuple(10000, vector<size_t>({9007}), 2048),
        make_tuple(10000, vector<size_t>({9999}), 2048),
        make_tuple(4096, vector<size_t>({0}), 4096),
        make_tuple(4096, vector<size_t>({4095}), 4096),
        make_tuple(16384, vector<size_t>({12288}), 4096),
        make_tuple(16384, vector<size_t>({12289}), 4096),
        make_tuple(16384, vector<size_t>({16383}), 4096),

        make_tuple(10000, vector<size_t>({5005}), POLY_MODULUS_DEGREE),
        make_tuple(10000, vector<size_t>({0}), POLY_MODULUS_DEGREE),
        make_tuple(10000, vector<size_t>({8191}), POLY_MODULUS_DEGREE),
        make_tuple(10000, vector<size_t>({0, 8191}), POLY_MODULUS_DEGREE),
        make_tuple(10000, vector<size_t>({0, 5005, 8191}), POLY_MODULUS_DEGREE),
        make_tuple(10000, vector<size_t>({0, 1, 2, 3, 4, 5}),
                   POLY_MODULUS_DEGREE)));

class ProcessResponseTest
    : public PIRClientTest,
      public testing::WithParamInterface<tuple<
          size_t, size_t, size_t, size_t, vector<size_t>, vector<size_t>>> {
 protected:
  void SetUpForCTMultiply(bool use_ciphertext_multiplication) {
    const auto dbsize = get<0>(GetParam());
    d_ = get<1>(GetParam());
    elem_size_ = get<2>(GetParam());
    pt_size_ = get<3>(GetParam());
    desired_indices_ = get<4>(GetParam());
    result_offsets_ = get<5>(GetParam());
    ASSERT_EQ(desired_indices_.size(), result_offsets_.size());

    SetUpDB(dbsize, d_, elem_size_, use_ciphertext_multiplication);

    prng_ = seal::UniformRandomGeneratorFactory::DefaultFactory()->create({99});

    ASSIGN_OR_FAIL(ct_reencoder_,
                   CiphertextReencoder::Create(Context()->SEALContext()));
  }

  vector<Ciphertext> DecompCT(Ciphertext input_ct) {
    vector<Ciphertext> result_cts({input_ct});
    for (size_t d = 0; d < d_ - 1; ++d) {
      vector<Ciphertext> inter_cts(result_cts.size() *
                                   ct_reencoder_->ExpansionRatio() *
                                   input_ct.size());
      auto inter_cts_iter = inter_cts.begin();
      for (const auto& ct : result_cts) {
        auto pts = ct_reencoder_->Encode(ct);
        for (const auto& pt : pts) {
          Encryptor()->encrypt(pt, *(inter_cts_iter++));
        }
      }
      result_cts = inter_cts;
    }
    return result_cts;
  }

  size_t d_;
  size_t elem_size_;
  size_t pt_size_;
  vector<size_t> desired_indices_;
  vector<size_t> result_offsets_;

  shared_ptr<UniformRandomGenerator> prng_;
  unique_ptr<CiphertextReencoder> ct_reencoder_;
};

TEST_P(ProcessResponseTest, TestProcessResponse) {
  SetUpForCTMultiply(false);
  vector<string> values(desired_indices_.size(), string(pt_size_, 0));
  for (size_t i = 0; i < values.size(); ++i) {
    prng_->generate(values[i].size(),
                    reinterpret_cast<seal::SEAL_BYTE*>(values[i].data()));
  }

  StringEncoder encoder(Context()->SEALContext());
  Response response;
  for (auto& value : values) {
    Plaintext pt;
    encoder.encode(value, pt);
    Ciphertext ct;
    Encryptor()->encrypt(pt, ct);
    SaveCiphertexts(DecompCT(ct), response.add_reply());
  }

  ASSIGN_OR_FAIL(auto result,
                 client_->ProcessResponse(desired_indices_, response));

  ASSERT_EQ(result.size(), values.size());
  for (size_t i = 0; i < result.size(); ++i) {
    EXPECT_EQ(result[i], values[i].substr(result_offsets_[i], elem_size_))
        << "i = " << i;
  }
}

TEST_P(ProcessResponseTest, TestProcessResponseCTMultiply) {
  SetUpForCTMultiply(true);
  vector<string> values(desired_indices_.size(), string(pt_size_, 0));
  for (size_t i = 0; i < values.size(); ++i) {
    prng_->generate(values[i].size(),
                    reinterpret_cast<seal::SEAL_BYTE*>(values[i].data()));
  }

  StringEncoder encoder(Context()->SEALContext());
  Response response;
  for (auto& value : values) {
    Plaintext pt;
    encoder.encode(value, pt);
    Ciphertext ct;
    Encryptor()->encrypt(pt, ct);
    SaveCiphertexts({ct}, response.add_reply());
  }

  ASSIGN_OR_FAIL(auto result,
                 client_->ProcessResponse(desired_indices_, response));

  ASSERT_EQ(result.size(), values.size());
  for (size_t i = 0; i < result.size(); ++i) {
    EXPECT_EQ(result[i], values[i].substr(result_offsets_[i], elem_size_))
        << "i = " << i;
  }
}

TEST_P(ProcessResponseTest, TestProcessResponseInteger) {
  SetUpForCTMultiply(false);
  vector<int64_t> values(desired_indices_.size());
  for (size_t i = 0; i < values.size(); ++i) {
    prng_->generate(sizeof(values[i]),
                    reinterpret_cast<seal::SEAL_BYTE*>(&values[i]));
  }

  Response response;
  for (auto& value : values) {
    Plaintext pt;
    Context()->Encoder()->encode(value, pt);
    Ciphertext ct;
    Encryptor()->encrypt(pt, ct);
    auto decomp_cts = DecompCT(ct);
    SaveCiphertexts(decomp_cts, response.add_reply());
  }

  ASSIGN_OR_FAIL(auto result, client_->ProcessResponseInteger(response));
  ASSERT_EQ(result.size(), values.size());
  for (size_t i = 0; i < result.size(); ++i) {
    ASSERT_EQ(result[i], values[i]);
  }
}

TEST_P(ProcessResponseTest, TestProcessResponseIntegerCTMultiply) {
  SetUpForCTMultiply(true);
  vector<int64_t> values(desired_indices_.size());
  for (size_t i = 0; i < values.size(); ++i) {
    prng_->generate(sizeof(values[i]),
                    reinterpret_cast<seal::SEAL_BYTE*>(&values[i]));
  }

  Response response;
  for (auto& value : values) {
    Plaintext pt;
    Context()->Encoder()->encode(value, pt);
    Ciphertext ct;
    Encryptor()->encrypt(pt, ct);
    SaveCiphertexts({ct}, response.add_reply());
  }

  ASSIGN_OR_FAIL(auto result, client_->ProcessResponseInteger(response));
  ASSERT_EQ(result.size(), values.size());
  for (size_t i = 0; i < result.size(); ++i) {
    ASSERT_EQ(result[i], values[i]);
  }
}

INSTANTIATE_TEST_SUITE_P(
    PIRClientProcessResponsesTests, ProcessResponseTest,
    testing::Values(
        make_tuple(1000, 1, 64, 7680, vector<size_t>({720, 777, 839}),
                   vector<size_t>({0, 3648, 7616})),
        make_tuple(1000, 2, 64, 7680, vector<size_t>({720, 777, 839}),
                   vector<size_t>({0, 3648, 7616})),
        make_tuple(1000, 3, 64, 7680, vector<size_t>({720, 777, 839}),
                   vector<size_t>({0, 3648, 7616})),
        make_tuple(1000, 4, 64, 7680, vector<size_t>({720, 777, 839}),
                   vector<size_t>({0, 3648, 7616}))));

}  // namespace pir
