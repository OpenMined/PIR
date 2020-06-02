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

#include "gtest/gtest.h"
#include "server.h"
#include "utils.h"

namespace pir {

using namespace seal;
using std::get;
using std::make_tuple;
using std::make_unique;
using std::tuple;

class PIRClientTest : public ::testing::Test {
 protected:
  static constexpr std::size_t DB_SIZE = 100;
  void SetUp() { SetUpDB(DB_SIZE); }

  void SetUpDB(size_t dbsize) {
    pir_params_ = PIRParameters::Create(dbsize);
    client_ = PIRClient::Create(pir_params_).ValueOrDie();

    ASSERT_TRUE(client_ != nullptr);
  }

  PIRContext* Context() { return client_->context_.get(); }
  std::shared_ptr<seal::Decryptor> Decryptor() { return client_->decryptor_; }
  std::shared_ptr<seal::Encryptor> Encryptor() { return client_->encryptor_; }

  std::shared_ptr<PIRParameters> pir_params_;
  std::unique_ptr<PIRClient> client_;
};

TEST_F(PIRClientTest, TestCreateRequest) {
  const size_t desired_index = 5;

  auto req_proto = client_->CreateRequest(desired_index).ValueOrDie();
  auto req =
      LoadCiphertexts(Context()->SEALContext(), req_proto.query()).ValueOrDie();

  Plaintext pt;
  ASSERT_EQ(req.size(), 1);
  Decryptor()->decrypt(req[0], pt);

  const auto plain_mod =
      pir_params_->GetEncryptionParams().plain_modulus().value();
  EXPECT_EQ((pt[desired_index] * next_power_two(DB_SIZE)) % plain_mod, 1);
  for (size_t i = 0; i < pt.coeff_count(); ++i) {
    if (i != desired_index) {
      EXPECT_EQ(pt[i], 0);
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

  Response reply;
  SaveCiphertexts(ct, reply.mutable_reply());

  auto result = client_->ProcessResponse(reply).ValueOrDie();
  ASSERT_EQ(result, value);
}

TEST_F(PIRClientTest, TestCreateRequest_InvalidIndex) {
  auto payload_or = client_->CreateRequest(DB_SIZE + 1);
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
  auto payload =
      LoadCiphertexts(Context()->SEALContext(), payload_or.ValueOrDie().query())
          .ValueOrDie();
  ASSERT_EQ(payload.size(), dbsize / poly_modulus_degree + 1);

  for (const auto& ct : payload) {
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
        make_tuple(10000, 5005, DEFAULT_POLY_MODULUS_DEGREE),
        make_tuple(10000, 0, DEFAULT_POLY_MODULUS_DEGREE),
        make_tuple(10000, 1, DEFAULT_POLY_MODULUS_DEGREE),
        make_tuple(10000, 3333, DEFAULT_POLY_MODULUS_DEGREE),
        make_tuple(10000, 4095, DEFAULT_POLY_MODULUS_DEGREE),
        make_tuple(10000, 4096, DEFAULT_POLY_MODULUS_DEGREE),
        make_tuple(10000, 4097, DEFAULT_POLY_MODULUS_DEGREE),
        make_tuple(10000, 8191, DEFAULT_POLY_MODULUS_DEGREE),
        make_tuple(10000, 8192, 2048), make_tuple(10000, 8193, 2048),
        make_tuple(10000, 9007, 2048), make_tuple(10000, 9999, 2048),
        make_tuple(4096, 0, 4096), make_tuple(4096, 4095, 4096),
        make_tuple(16384, 12288, 4096), make_tuple(16384, 12289, 4096),
        make_tuple(16384, 16383, 4096)));

}  // namespace pir
