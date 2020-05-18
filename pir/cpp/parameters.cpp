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
#include "parameters.h"

#include "seal/seal.h"

namespace pir {

seal::EncryptionParameters generateEncryptionParams(
    uint32_t poly_modulus_degree /*= 4096*/) {
  auto plain_modulus = seal::PlainModulus::Batching(poly_modulus_degree, 20);
  seal::EncryptionParameters parms(seal::scheme_type::BFV);
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_plain_modulus(plain_modulus);
  auto coeff = seal::CoeffModulus::BFVDefault(poly_modulus_degree);
  parms.set_coeff_modulus(coeff);

  return parms;
}

}  // namespace pir
