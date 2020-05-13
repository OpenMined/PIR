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

#include "seal/seal.h"

#include "gtest/gtest.h"

namespace pir {

using namespace seal;

class SEALTest : public ::testing::Test {
 protected:
  void SetUp() {}
  void TearDown() {}
};

TEST_F(SEALTest, TestSanity) {
  // config
  uint32_t poly_modulus_degree = 4096, plain_modulus = 1032193;

  // params
  EncryptionParameters parms(scheme_type::BFV);
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_plain_modulus(plain_modulus);
  auto coeff =
      CoeffModulus::BFVDefault(poly_modulus_degree, sec_level_type::tc128);
  parms.set_coeff_modulus(coeff);

  // context
  auto context = SEALContext::Create(parms, true, sec_level_type::tc128);
  KeyGenerator keygen(context);

  IntegerEncoder encoder(context);
  Encryptor encryptor(context, keygen.public_key());
  Evaluator evaluator(context);
  Decryptor decryptor(context, keygen.secret_key());

  // evaluator
  Ciphertext encrypted;
  Plaintext plain;
  encryptor.encrypt(encoder.encode(0x12345678), encrypted);
  plain = "2";
  evaluator.multiply_plain_inplace(encrypted, plain);
  decryptor.decrypt(encrypted, plain);
  ASSERT_EQ(static_cast<uint64_t>(2 * 0x12345678),
            encoder.decode_uint64(plain));
}

}  // namespace pir
