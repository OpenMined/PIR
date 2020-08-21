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

#ifndef PIR_TEST_UTILS_H
#define PIR_TEST_UTILS_H

#include <memory>
#include <string>
#include <vector>

#include "pir/cpp/database.h"
#include "pir/proto/payload.pb.h"
#include "seal/seal.h"

namespace pir {

using std::int64_t;
using std::shared_ptr;
using std::string;
using std::unique_ptr;
using std::vector;

using namespace seal;

constexpr uint32_t POLY_MODULUS_DEGREE = 4096;

// Utility function to generate a vector of testing data
vector<string> generate_test_db(size_t db_size, size_t elem_size,
                                uint64_t seed = 42);

class PIRTestingBase {
 public:
  PIRTestingBase() {}
  virtual ~PIRTestingBase() {}

 protected:
  // Generate the EncryptParameters and PIRParameters and validate them.
  void SetUpParams(size_t db_size, size_t elem_size, size_t dimensions = 1,
                   uint32_t poly_modulus_degree = POLY_MODULUS_DEGREE,
                   uint32_t plain_mod_bit_size = 20,
                   uint32_t bits_per_coeff = 0,
                   bool use_ciphertext_multiplication = false);

  // Genrate a DB of random values
  void GenerateDB(uint32_t seed = 42);
  void GenerateIntDB(uint32_t seed = 42);

  void SetUpSealTools();

  size_t db_size_;
  vector<string> string_db_;
  vector<int64_t> int_db_;
  shared_ptr<SEALContext> seal_context_;
  shared_ptr<PIRParameters> pir_params_;
  shared_ptr<PIRDatabase> pir_db_;
  unique_ptr<KeyGenerator> keygen_;
  unique_ptr<Encryptor> encryptor_;
  unique_ptr<Decryptor> decryptor_;
};
}  // namespace pir

#endif  // PIR_TEST_UTILS_H
