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
#include "pir/cpp/test_base.h"

#include "gtest/gtest.h"
#include "pir/cpp/parameters.h"
#include "pir/cpp/status_asserts.h"
#include "pir/cpp/utils.h"

namespace pir {

using absl::make_unique;

vector<string> generate_test_db(size_t db_size, size_t elem_size,
                                uint64_t seed) {
  auto prng =
      seal::UniformRandomGeneratorFactory::DefaultFactory()->create({seed});
  vector<string> db(db_size, string(elem_size, 0));
  for (size_t i = 0; i < db_size; ++i) {
    prng->generate(db[i].size(),
                   reinterpret_cast<seal::SEAL_BYTE*>(db[i].data()));
  }
  return db;
}

void PIRTestingBase::SetUpParams(size_t db_size, size_t elem_size,
                                 size_t dimensions,
                                 uint32_t poly_modulus_degree,
                                 uint32_t plain_mod_bit_size,
                                 uint32_t bits_per_coeff,
                                 bool use_ciphertext_multiplication) {
  db_size_ = db_size;

  auto encryption_params =
      GenerateEncryptionParams(poly_modulus_degree, plain_mod_bit_size);

  seal_context_ = seal::SEALContext::Create(encryption_params);
  if (!seal_context_->parameters_set()) {
    FAIL() << "Error setting encryption parameters: "
           << seal_context_->parameter_error_message();
  }

  ASSIGN_OR_FAIL(
      pir_params_,
      CreatePIRParameters(db_size, elem_size, dimensions, encryption_params,
                          use_ciphertext_multiplication, bits_per_coeff));
}

void PIRTestingBase::GenerateDB(uint32_t seed) {
  string_db_ = generate_test_db(db_size_, pir_params_->bytes_per_item(), seed);
  ASSIGN_OR_FAIL(pir_db_, PIRDatabase::Create(string_db_, pir_params_));
}

void PIRTestingBase::GenerateIntDB(uint32_t seed) {
  auto prng =
      seal::UniformRandomGeneratorFactory::DefaultFactory()->create({seed});
  int_db_.resize(db_size_, 0);
  for (size_t i = 0; i < db_size_; ++i) {
    // can't use full size, or will run out of room on decode when multiplied by
    // selection vector
    prng->generate(sizeof(int_db_[i]) - 2,
                   reinterpret_cast<seal::SEAL_BYTE*>(&int_db_[i]));
  }
  ASSIGN_OR_FAIL(pir_db_, PIRDatabase::Create(int_db_, pir_params_));
}

void PIRTestingBase::SetUpSealTools() {
  keygen_ = make_unique<KeyGenerator>(seal_context_);
  encryptor_ = make_unique<Encryptor>(seal_context_, keygen_->public_key());
  decryptor_ = make_unique<Decryptor>(seal_context_, keygen_->secret_key());
}

}  // namespace pir
