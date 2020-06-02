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

#include "pir/cpp/serialization.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "pir/cpp/context.h"
#include "pir/cpp/utils.h"
#include "seal/seal.h"
#include "util/statusor.h"

namespace pir {

using namespace seal;
using std::get;
using std::make_tuple;
using std::make_unique;
using std::tuple;

using ::testing::ElementsAreArray;

class PIRSerializationTest : public ::testing::Test {
 protected:
  static constexpr std::size_t DB_SIZE = 100;
  void SetUp() { SetUpDB(DB_SIZE); }

  void SetUpDB(size_t dbsize) {
    pir_params_ = PIRParameters::Create(dbsize);
    context_ = std::move(PIRContext::Create(pir_params_).ValueOrDie());

    auto keygen_ =
        std::make_unique<seal::KeyGenerator>(context_->SEALContext());
    encryptor_ = std::make_shared<seal::Encryptor>(context_->SEALContext(),
                                                   keygen_->public_key());
    decryptor_ = std::make_shared<seal::Decryptor>(context_->SEALContext(),
                                                   keygen_->secret_key());
  }

  std::shared_ptr<PIRParameters> pir_params_;
  std::shared_ptr<PIRContext> context_;
  std::shared_ptr<seal::Encryptor> encryptor_;
  std::shared_ptr<seal::Decryptor> decryptor_;
};

TEST_F(PIRSerializationTest, TestResponseSerialization) {
  int64_t value = 987654321;
  Plaintext pt, reloaded_pt;
  context_->Encoder()->encode(value, pt);
  vector<Ciphertext> ct(1);
  encryptor_->encrypt(pt, ct[0]);

  Response response_proto;
  SaveCiphertexts(ct, response_proto.mutable_reply());

  auto reloaded_or =
      LoadCiphertexts(context_->SEALContext(), response_proto.reply());
  ASSERT_TRUE(reloaded_or.ok())
      << "Status is: " << reloaded_or.status().ToString();

  auto reloaded = reloaded_or.ValueOrDie();
  ASSERT_EQ(reloaded.size(), 1);
  decryptor_->decrypt(reloaded[0], reloaded_pt);
  EXPECT_THAT(reloaded_pt, pt);
}

TEST_F(PIRSerializationTest, TestRequestSerialization) {
  int64_t value = 987654321;
  Plaintext pt, reloaded_pt;
  context_->Encoder()->encode(value, pt);
  vector<Ciphertext> ct(1);
  encryptor_->encrypt(pt, ct[0]);

  auto keygen_ = make_unique<KeyGenerator>(context_->SEALContext());
  auto elts = generate_galois_elts(DEFAULT_POLY_MODULUS_DEGREE);
  GaloisKeys gal_keys = keygen_->galois_keys_local(elts);

  Request request_proto;
  SaveCiphertexts(ct, request_proto.mutable_query());
  SEALSerialize<GaloisKeys>(gal_keys, request_proto.mutable_keys());

  auto request_or =
      LoadCiphertexts(context_->SEALContext(), request_proto.query());
  ASSERT_TRUE(request_or.ok())
      << "Status is: " << request_or.status().ToString();

  auto request = request_or.ValueOrDie();
  auto keys_or = SEALDeserialize<GaloisKeys>(context_->SEALContext(),
                                             request_proto.keys());
  ASSERT_TRUE(keys_or.ok()) << "Status is: " << keys_or.status().ToString();
  auto keys = keys_or.ValueOrDie();

  ASSERT_EQ(request.size(), 1);
  decryptor_->decrypt(request[0], reloaded_pt);
  ASSERT_EQ(reloaded_pt, pt);

  for (auto &elt : elts) ASSERT_TRUE(keys.has_key(elt));
}

}  // namespace pir
