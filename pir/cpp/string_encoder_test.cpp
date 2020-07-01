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

#include "pir/cpp/string_encoder.h"

#include <iostream>
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

using namespace seal;
using namespace testing;

constexpr size_t POLY_MODULUS_DEGREE = 4096;

class StringEncoderTest : public ::testing::Test {
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
    evaluator_ = make_unique<Evaluator>(seal_context_);
    decryptor_ = make_unique<Decryptor>(seal_context_, keygen_->secret_key());
    encoder_ = std::make_unique<StringEncoder>(seal_context_);
  }

  shared_ptr<SEALContext> seal_context_;
  unique_ptr<StringEncoder> encoder_;
  unique_ptr<KeyGenerator> keygen_;
  unique_ptr<Encryptor> encryptor_;
  unique_ptr<Evaluator> evaluator_;
  unique_ptr<Decryptor> decryptor_;
};

TEST_F(StringEncoderTest, TestEncodeDecode) {
  string value("This is a string test for random VALUES@!#");
  size_t num_coeff = ceil((value.size() * 8) / 19.0);
  Plaintext pt;
  auto status = encoder_->encode(value, pt);
  EXPECT_TRUE(status.ok()) << status.ToString();
  EXPECT_EQ(pt.coeff_count(), num_coeff);
  auto result = encoder_->decode(pt).ValueOrDie();
  ASSERT_GE(result.size(), value.size());
  EXPECT_EQ(result.substr(0, value.size()), value);
  EXPECT_THAT(result.substr(value.size()), Each(0));
}

TEST_F(StringEncoderTest, TestEncodeDecodePRN) {
  auto prng =
      seal::UniformRandomGeneratorFactory::DefaultFactory()->create({42});
  string v(9728, 0);
  prng->generate(v.size(), reinterpret_cast<SEAL_BYTE *>(v.data()));
  Plaintext pt;
  auto status = encoder_->encode(v, pt);
  EXPECT_TRUE(status.ok()) << status.ToString();
  auto result = encoder_->decode(pt).ValueOrDie();
  ASSERT_GE(result.size(), v.size());
  EXPECT_EQ(result.substr(0, v.size()), v);
  EXPECT_THAT(result.substr(v.size()), Each(0));
}

TEST_F(StringEncoderTest, TestEncodeDecodeVector) {
  auto prng =
      seal::UniformRandomGeneratorFactory::DefaultFactory()->create({42});
  vector<string> v(152);
  for (auto &s : v) {
    s.resize(64);
    prng->generate(s.size(), reinterpret_cast<SEAL_BYTE *>(s.data()));
  }

  for (const auto &s : v) {
    EXPECT_THAT(s, SizeIs(64));
    EXPECT_THAT(s, Not(Each(0)));
  }

  Plaintext pt;
  auto status = encoder_->encode(v.begin(), v.end(), pt);
  EXPECT_TRUE(status.ok()) << status.ToString();
  size_t offset = 0;
  for (size_t i = 0; i < v.size(); ++i) {
    auto result = encoder_->decode(pt, v[i].size(), offset);
    offset += v[i].size();
    ASSERT_THAT(result.ok(), IsTrue())
        << "i = " << i << ", error: " << result.status().ToString();
    EXPECT_THAT(result.ValueOrDie(), StrEq(v[i])) << "i = " << i;
  }
}

TEST_F(StringEncoderTest, TestEncodeDecodeTooBig) {
  auto prng =
      seal::UniformRandomGeneratorFactory::DefaultFactory()->create({42});
  string v(9729, 0);
  prng->generate(v.size(), reinterpret_cast<SEAL_BYTE *>(v.data()));
  Plaintext pt;
  auto status = encoder_->encode(v, pt);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(status.code(),
            private_join_and_compute::StatusCode::kInvalidArgument);
}

TEST_F(StringEncoderTest, TestEncodeVectorTooBig) {
  auto prng =
      seal::UniformRandomGeneratorFactory::DefaultFactory()->create({42});
  vector<string> v(141);
  for (auto &s : v) {
    s.resize(69);
    prng->generate(s.size(), reinterpret_cast<SEAL_BYTE *>(s.data()));
  }

  Plaintext pt;
  auto status = encoder_->encode(v.begin(), v.end(), pt);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(status.code(),
            private_join_and_compute::StatusCode::kInvalidArgument);
}

TEST_F(StringEncoderTest, TestDecodeTooBig) {
  auto prng =
      seal::UniformRandomGeneratorFactory::DefaultFactory()->create({42});
  string v(9728, 0);
  prng->generate(v.size(), reinterpret_cast<SEAL_BYTE *>(v.data()));
  Plaintext pt;
  auto status = encoder_->encode(v, pt);
  EXPECT_TRUE(status.ok()) << status.ToString();
  auto result_or = encoder_->decode(pt, 100, 9629);
  EXPECT_FALSE(result_or.status().ok());
  EXPECT_EQ(result_or.status().code(),
            private_join_and_compute::StatusCode::kInvalidArgument);
}

TEST_F(StringEncoderTest, TestEncOp) {
  auto prng =
      seal::UniformRandomGeneratorFactory::DefaultFactory()->create({42});
  string v(9728, 0);
  prng->generate(v.size(), reinterpret_cast<SEAL_BYTE *>(v.data()));
  Plaintext pt;
  auto status = encoder_->encode(v, pt);
  EXPECT_TRUE(status.ok()) << status.ToString();

  Plaintext selection_vector_pt(POLY_MODULUS_DEGREE);
  selection_vector_pt.set_zero();
  selection_vector_pt[0] = 1;
  Ciphertext selection_vector_ct;
  encryptor_->encrypt(selection_vector_pt, selection_vector_ct);

  evaluator_->multiply_plain_inplace(selection_vector_ct, pt);

  Plaintext result_pt;
  decryptor_->decrypt(selection_vector_ct, result_pt);
  auto result = encoder_->decode(result_pt).ValueOrDie();
  ASSERT_GE(result.size(), v.size());
  EXPECT_EQ(result.substr(0, v.size()), v);
  EXPECT_THAT(result.substr(v.size()), Each(0));
}

}  // namespace
}  // namespace pir
