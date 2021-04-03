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

#include "absl/status/statusor.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "pir/cpp/context.h"
#include "pir/cpp/status_asserts.h"
#include "pir/cpp/utils.h"
#include "seal/seal.h"

namespace pir {

using namespace seal;
using std::get;
using std::make_tuple;
using std::make_unique;
using std::size_t;
using std::tuple;

using ::testing::ElementsAreArray;

class PIRSerializationTest : public ::testing::Test {
 protected:
  static constexpr size_t DB_SIZE = 100;
  static constexpr size_t ELEM_SIZE = 64;
  void SetUp() { SetUpDB(DB_SIZE); }

  void SetUpDB(size_t dbsize) {
    auto pir_params = *(CreatePIRParameters(dbsize, ELEM_SIZE));
    context_ = std::move(*(PIRContext::Create(pir_params)));

    auto keygen_ =
        std::make_unique<seal::KeyGenerator>(context_->SEALContext());
    encryptor_ = std::make_shared<seal::Encryptor>(context_->SEALContext(),
                                                   keygen_->public_key());
    decryptor_ = std::make_shared<seal::Decryptor>(context_->SEALContext(),
                                                   keygen_->secret_key());
  }

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
  SaveCiphertexts(ct, response_proto.add_reply());

  ASSIGN_OR_FAIL(auto reloaded, LoadCiphertexts(context_->SEALContext(),
                                                response_proto.reply(0)));
  ASSERT_EQ(reloaded.size(), 1);
  decryptor_->decrypt(reloaded[0], reloaded_pt);
  EXPECT_THAT(reloaded_pt, pt);
}

TEST_F(PIRSerializationTest, TestRequestSerialization_IndividualMethods) {
  int64_t value = 987654321;
  Plaintext pt, reloaded_pt;
  context_->Encoder()->encode(value, pt);
  vector<Ciphertext> ct(1);
  encryptor_->encrypt(pt, ct[0]);

  auto keygen_ = make_unique<KeyGenerator>(context_->SEALContext());
  auto elts = generate_galois_elts(DEFAULT_POLY_MODULUS_DEGREE);
  GaloisKeys gal_keys = keygen_->galois_keys_local(elts);
  RelinKeys relin_keys = keygen_->relin_keys_local();

  Request request_proto;
  SaveCiphertexts(ct, request_proto.add_query());
  SEALSerialize<GaloisKeys>(gal_keys, request_proto.mutable_galois_keys());
  SEALSerialize<RelinKeys>(relin_keys, request_proto.mutable_relin_keys());

  ASSIGN_OR_FAIL(auto request, LoadCiphertexts(context_->SEALContext(),
                                               request_proto.query(0)));
  ASSERT_EQ(request.size(), 1);
  decryptor_->decrypt(request[0], reloaded_pt);

  ASSIGN_OR_FAIL(auto gal_keys_post,
                 SEALDeserialize<GaloisKeys>(context_->SEALContext(),
                                             request_proto.galois_keys()));
  for (const auto& e : elts) {
    // Can't really test equality of the keys, so just check that they exist.
    ASSERT_TRUE(gal_keys_post.has_key(e));
  }

  ASSIGN_OR_FAIL(auto relin_keys_post,
                 SEALDeserialize<RelinKeys>(context_->SEALContext(),
                                            request_proto.relin_keys()));
  // Can't really check if the relin keys are valid. Just assume it's ok here.
}

TEST_F(PIRSerializationTest, TestRequestSerialization_Shortcut) {
  int64_t value = 987654321;
  Plaintext pt, reloaded_pt;
  context_->Encoder()->encode(value, pt);
  vector<Ciphertext> ct(1);
  encryptor_->encrypt(pt, ct[0]);

  Request request_proto;
  SaveRequest({ct}, &request_proto);

  ASSIGN_OR_FAIL(auto request, LoadCiphertexts(context_->SEALContext(),
                                               request_proto.query(0)));
  ASSERT_EQ(request.size(), 1);
  decryptor_->decrypt(request[0], reloaded_pt);

  ASSERT_THAT(request_proto.galois_keys(), testing::IsEmpty());
  ASSERT_THAT(request_proto.relin_keys(), testing::IsEmpty());
}

TEST_F(PIRSerializationTest, TestRequestSerialization_ShortcutWithRelin) {
  int64_t value = 987654321;
  Plaintext pt, reloaded_pt;
  context_->Encoder()->encode(value, pt);
  vector<Ciphertext> ct(1);
  encryptor_->encrypt(pt, ct[0]);

  auto keygen_ = make_unique<KeyGenerator>(context_->SEALContext());
  auto elts = generate_galois_elts(DEFAULT_POLY_MODULUS_DEGREE);
  GaloisKeys gal_keys = keygen_->galois_keys_local(elts);
  RelinKeys relin_keys = keygen_->relin_keys_local();

  Request request_proto;
  SaveRequest({ct}, gal_keys, relin_keys, &request_proto);

  ASSIGN_OR_FAIL(auto request, LoadCiphertexts(context_->SEALContext(),
                                               request_proto.query(0)));
  ASSERT_EQ(request.size(), 1);
  decryptor_->decrypt(request[0], reloaded_pt);

  ASSIGN_OR_FAIL(auto gal_keys_post,
                 SEALDeserialize<GaloisKeys>(context_->SEALContext(),
                                             request_proto.galois_keys()));
  for (const auto& e : elts) {
    // Can't really test equality of the keys, so just check that they exists.
    ASSERT_TRUE(gal_keys_post.has_key(e));
  }

  ASSIGN_OR_FAIL(auto relin_keys_post,
                 SEALDeserialize<RelinKeys>(context_->SEALContext(),
                                            request_proto.relin_keys()));
  // Can't really check if the relin keys are valid. Just assume it's ok here.
}

TEST_F(PIRSerializationTest, TestEncryptionParamsSerialization) {
  auto params = GenerateEncryptionParams();
  std::string serial;
  ASSERT_OK(SEALSerialize<EncryptionParameters>(params, &serial));
  ASSIGN_OR_FAIL(auto decoded_params,
                 SEALDeserialize<EncryptionParameters>(serial));
  ASSERT_EQ(params.plain_modulus(), decoded_params.plain_modulus());
  ASSERT_EQ(params.poly_modulus_degree(), decoded_params.poly_modulus_degree());
}
}  // namespace pir
