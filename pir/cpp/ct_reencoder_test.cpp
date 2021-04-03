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
#include "pir/cpp/status_asserts.h"
#include "pir/cpp/string_encoder.h"

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

string generate_string(size_t size) {
  static auto prng =
      seal::UniformRandomGeneratorFactory::DefaultFactory()->create({42});
  string result(size, 0);
  prng->generate(size, reinterpret_cast<seal::SEAL_BYTE*>(result.data()));
  return result;
}

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
    encoder_ = make_unique<StringEncoder>(seal_context_);
    ct_reencoder_ = *(CiphertextReencoder::Create(seal_context_));
  }

  string GenerateSampleString() {
    return generate_string(encoder_->max_bytes_per_plaintext());
  }

  shared_ptr<SEALContext> seal_context_;
  unique_ptr<CiphertextReencoder> ct_reencoder_;
  unique_ptr<StringEncoder> encoder_;
  unique_ptr<KeyGenerator> keygen_;
  unique_ptr<Encryptor> encryptor_;
  unique_ptr<Decryptor> decryptor_;
};

TEST_F(CiphertextReencoderTest, TextExpansionRatio) {
  EXPECT_EQ(ct_reencoder_->ExpansionRatio(), 4);
}

TEST_F(CiphertextReencoderTest, TestEncodeDecode) {
  string value = GenerateSampleString();
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
  ASSIGN_OR_FAIL(auto result, encoder_->decode(result_pt));
  EXPECT_EQ(result, value);
}

TEST_F(CiphertextReencoderTest, TestRecursion) {
  string value = GenerateSampleString();
  Plaintext pt;
  encoder_->encode(value, pt);

  // level 1
  Ciphertext ct;
  encryptor_->encrypt(pt, ct);
  auto pt_lvl_1 = ct_reencoder_->Encode(ct);
  size_t exp_ratio = ct.size() * ct_reencoder_->ExpansionRatio();
  ASSERT_EQ(pt_lvl_1.size(), exp_ratio);

  // level 2
  vector<Plaintext> pt_lvl_2;
  pt_lvl_2.reserve(pt_lvl_1.size() * exp_ratio);
  for (size_t i = 0; i < pt_lvl_1.size(); ++i) {
    Ciphertext ct;
    encryptor_->encrypt(pt_lvl_1[i], ct);
    auto pts = ct_reencoder_->Encode(ct);
    pt_lvl_2.insert(pt_lvl_2.end(), pts.begin(), pts.end());
  }
  ASSERT_EQ(pt_lvl_2.size(), exp_ratio * exp_ratio);

  // decode level 2
  vector<Plaintext> result_pt_lvl_1(exp_ratio);
  for (size_t i = 0; i < exp_ratio; ++i) {
    auto result_ct =
        ct_reencoder_->Decode(pt_lvl_2.begin() + (i * exp_ratio), ct.size());
    decryptor_->decrypt(result_ct, result_pt_lvl_1[i]);
  }

  // decode level 1
  auto result_ct = ct_reencoder_->Decode(result_pt_lvl_1);
  Plaintext result_pt;
  decryptor_->decrypt(result_ct, result_pt);
  EXPECT_EQ(result_pt, pt);
  ASSIGN_OR_FAIL(auto result, encoder_->decode(result_pt));
  EXPECT_EQ(result, value);
}

TEST_F(CiphertextReencoderTest, TestEncryptDecrypt) {
  string value = GenerateSampleString();
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
  ASSIGN_OR_FAIL(auto result, encoder_->decode(result_pt));
  EXPECT_EQ(result, value);
}

TEST_F(CiphertextReencoderTest, TestMultOneEnc) {
  string value = GenerateSampleString();
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
  ASSIGN_OR_FAIL(auto result, encoder_->decode(result_pt));
  EXPECT_EQ(result, value);
}

}  // namespace
}  // namespace pir
