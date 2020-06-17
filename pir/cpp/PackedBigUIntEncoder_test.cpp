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

#include "pir/cpp/PackedBigUIntEncoder.h"

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

constexpr size_t POLY_MODULUS_DEGREE = 4096;

class PackedBigUIntEncoderTest : public ::testing::Test {
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
    encoder_ = std::make_unique<PackedBigUIntEncoder>(seal_context_);
  }

  shared_ptr<SEALContext> seal_context_;
  unique_ptr<PackedBigUIntEncoder> encoder_;
  unique_ptr<KeyGenerator> keygen_;
  unique_ptr<Encryptor> encryptor_;
  unique_ptr<Evaluator> evaluator_;
  unique_ptr<Decryptor> decryptor_;
};

TEST_F(PackedBigUIntEncoderTest, TestEncodeDecode) {
  BigUInt value("DEADBEEF12345678909876543210010BEEFDEAD");
  Plaintext pt;
  encoder_->encode(value, pt);
  cout << "Got PT " << pt.to_string() << endl;
  BigUInt result = encoder_->decode(pt);
  EXPECT_EQ(result, value);
}

TEST_F(PackedBigUIntEncoderTest, TestEncodeDecodePRN) {
  auto prng =
      seal::UniformRandomGeneratorFactory::DefaultFactory()->create({42});
  std::array<uint64_t, 32> v;
  prng->generate(sizeof(v), reinterpret_cast<SEAL_BYTE *>(v.data()));
  BigUInt value(sizeof(v) * 8, v.data());
  std::cout << "v = " << value.to_string() << std::endl;
  Plaintext pt;
  encoder_->encode(value, pt);
  cout << "Got PT " << pt.to_string() << endl;
  BigUInt result = encoder_->decode(pt);
  EXPECT_EQ(result, value);
}

TEST_F(PackedBigUIntEncoderTest, TestEncOp) {
  auto prng =
      seal::UniformRandomGeneratorFactory::DefaultFactory()->create({42});
  std::array<uint64_t, 32> v;
  prng->generate(sizeof(v), reinterpret_cast<SEAL_BYTE *>(v.data()));
  BigUInt value(sizeof(v) * 8, v.data());
  Plaintext pt;
  encoder_->encode(value, pt);
  cout << "Got PT " << pt.to_string() << endl;

  Plaintext selection_vector_pt(POLY_MODULUS_DEGREE);
  selection_vector_pt.set_zero();
  selection_vector_pt[0] = 1;
  cout << "SV PT " << selection_vector_pt.to_string() << endl;
  Ciphertext selection_vector_ct;
  encryptor_->encrypt(selection_vector_pt, selection_vector_ct);
  cout << "Initial noise budget: "
       << decryptor_->invariant_noise_budget(selection_vector_ct) << endl;

  evaluator_->multiply_plain_inplace(selection_vector_ct, pt);
  cout << "Noise budget after multiply: "
       << decryptor_->invariant_noise_budget(selection_vector_ct) << endl;

  Plaintext result_pt;
  decryptor_->decrypt(selection_vector_ct, result_pt);
  cout << "Result PT " << result_pt.to_string() << endl;
  BigUInt result = encoder_->decode(result_pt);
  EXPECT_EQ(result, value);
}

TEST_F(PackedBigUIntEncoderTest, TestSelectionVector) {
  constexpr size_t db_size = 10;
  constexpr size_t desired_index = 7;
  auto prng =
      seal::UniformRandomGeneratorFactory::DefaultFactory()->create({42});
  vector<BigUInt> db;
  db.reserve(db_size);
  std::array<std::array<uint64_t, 32>, db_size> v;
  for (size_t i = 0; i < db_size; ++i) {
    prng->generate(sizeof(v[i]), reinterpret_cast<SEAL_BYTE *>(v[i].data()));
    db.emplace_back(sizeof(v[i]) * 8, v[i].data());
    cout << "db[" << i << "] = " << db.back().to_string() << endl;
  }

  vector<Plaintext> pt_db(db_size);
  for (size_t i = 0; i < db_size; ++i) {
    cout << "db[" << i << "] = " << db[i].to_string() << endl;
    encoder_->encode(db[i], pt_db[i]);
    cout << "pt_db[" << i << "] = " << pt_db[i].to_string() << endl;
  }

  vector<Plaintext> selection_vector_pt(db_size);
  vector<Ciphertext> selection_vector_ct(db_size);
  for (size_t i = 0; i < db_size; ++i) {
    selection_vector_pt[i].resize(POLY_MODULUS_DEGREE);
    selection_vector_pt[i].set_zero();
    if (i == desired_index) {
      selection_vector_pt[i][0] = 1;
    }
    cout << "SV[" << i << "] = " << selection_vector_pt[i].to_string() << endl;
    encryptor_->encrypt(selection_vector_pt[i], selection_vector_ct[i]);
  }

  cout << "Initial noise budget: "
       << decryptor_->invariant_noise_budget(selection_vector_ct[0]) << endl;

  for (size_t i = 0; i < db_size; ++i) {
    evaluator_->multiply_plain_inplace(selection_vector_ct[i], pt_db[i]);
    cout << "Noise budget after multiply: "
         << decryptor_->invariant_noise_budget(selection_vector_ct[i]) << endl;
  }

  Ciphertext result_ct;
  evaluator_->add_many(selection_vector_ct, result_ct);
  cout << "Noise budget after sum: "
       << decryptor_->invariant_noise_budget(result_ct) << endl;

  Plaintext result_pt;
  decryptor_->decrypt(result_ct, result_pt);
  cout << "Result PT " << result_pt.to_string() << endl;
  BigUInt result = encoder_->decode(result_pt);
  EXPECT_EQ(result, db[desired_index]);
}

}  // namespace
}  // namespace pir
