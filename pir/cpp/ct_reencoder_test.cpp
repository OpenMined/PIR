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

#include "pir/cpp/ct_reencoder.h"

#include <memory>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "pir/cpp/parameters.h"

namespace pir {
namespace {

using std::cout;
using std::endl;
using std::make_unique;
using std::unique_ptr;
using std::vector;

using namespace seal;
using namespace ::testing;

constexpr size_t POLY_MODULUS_DEGREE = 4096;

class CiphertextReencoderTest : public ::testing::Test {
 protected:
  void SetUp() {
    auto params = GenerateEncryptionParams(POLY_MODULUS_DEGREE);
    seal_context_ = seal::SEALContext::Create(params);
    if (!seal_context_->parameters_set()) {
      FAIL() << "Error setting encryption parameters: "
             << seal_context_->parameter_error_message();
    }
    keygen_ = make_unique<KeyGenerator>(seal_context_);
    encryptor_ = make_unique<Encryptor>(seal_context_, keygen_->public_key());
    decryptor_ = make_unique<Decryptor>(seal_context_, keygen_->secret_key());
    encoder_ = make_unique<IntegerEncoder>(seal_context_);
    ct_reencoder_ = CiphertextReencoder::Create(seal_context_).ValueOrDie();
  }

  shared_ptr<SEALContext> seal_context_;
  unique_ptr<CiphertextReencoder> ct_reencoder_;
  unique_ptr<IntegerEncoder> encoder_;
  unique_ptr<KeyGenerator> keygen_;
  unique_ptr<Encryptor> encryptor_;
  unique_ptr<Decryptor> decryptor_;
};

TEST_F(CiphertextReencoderTest, TextExpansionRatio) {
  EXPECT_EQ(ct_reencoder_->ExpansionRatio(), 4);
}

TEST_F(CiphertextReencoderTest, TestEncodeDecode) {
  uint64_t value = 0xDEADBEEF12345678LL;
  Plaintext pt;
  encoder_->encode(value, pt);
  Ciphertext ct;
  encryptor_->encrypt(pt, ct);
  auto pt_decomp = ct_reencoder_->Encode(ct);
  ASSERT_EQ(pt_decomp.size(), ct.size() * ct_reencoder_->ExpansionRatio());
  auto result_ct = ct_reencoder_->Decode(pt_decomp);
  Plaintext result_pt;
  decryptor_->decrypt(result_ct, result_pt);
  EXPECT_EQ(result_pt, pt);
  auto result = encoder_->decode_uint64(result_pt);
  EXPECT_EQ(result, value);
}

TEST_F(CiphertextReencoderTest, TestEncryptDecrypt) {
  uint64_t value = 0xDEADBEEF12345678LL;
  Plaintext pt;
  encoder_->encode(value, pt);
  Ciphertext ct;
  encryptor_->encrypt(pt, ct);
  auto pt_decomp = ct_reencoder_->Encode(ct);
  ASSERT_EQ(pt_decomp.size(), ct.size() * ct_reencoder_->ExpansionRatio());

  vector<Ciphertext> cts(pt_decomp.size());
  for (size_t i = 0; i < cts.size(); ++i) {
    encryptor_->encrypt(pt_decomp[i], cts[i]);
  }

  vector<Plaintext> pts(pt_decomp.size());
  for (size_t i = 0; i < cts.size(); ++i) {
    decryptor_->decrypt(cts[i], pts[i]);
  }

  auto result_ct = ct_reencoder_->Decode(pts);
  Plaintext result_pt;
  decryptor_->decrypt(result_ct, result_pt);
  EXPECT_EQ(result_pt, pt);
  auto result = encoder_->decode_uint64(result_pt);
  EXPECT_EQ(result, value);
}

TEST_F(CiphertextReencoderTest, TestMultOneEnc) {
  uint64_t value = 0xDEADBEEF12345678LL;
  Plaintext pt;
  encoder_->encode(value, pt);
  Ciphertext ct;
  encryptor_->encrypt(pt, ct);
  auto pt_decomp = ct_reencoder_->Encode(ct);
  ASSERT_EQ(pt_decomp.size(), ct.size() * ct_reencoder_->ExpansionRatio());

  Plaintext one_pt(1);
  one_pt[0] = 1;
  Ciphertext one_ct;
  encryptor_->encrypt(one_pt, one_ct);

  Evaluator eval(seal_context_);
  vector<Ciphertext> cts(pt_decomp.size());
  for (size_t i = 0; i < cts.size(); ++i) {
    eval.multiply_plain(one_ct, pt_decomp[i], cts[i]);
  }

  vector<Plaintext> pts(pt_decomp.size());
  for (size_t i = 0; i < cts.size(); ++i) {
    decryptor_->decrypt(cts[i], pts[i]);
  }

  auto result_ct = ct_reencoder_->Decode(pts);
  Plaintext result_pt;
  decryptor_->decrypt(result_ct, result_pt);
  // EXPECT_EQ(result_pt, pt);
  auto result = encoder_->decode_uint64(result_pt);
  EXPECT_EQ(result, value);
}

}  // namespace
}  // namespace pir
