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

namespace pir {

void PackedBigUIntEncoder::encode(BigUInt value, Plaintext &destination) const {
  const auto params = context_->first_context_data()->parms();
  const auto poly_modulus_degree = params.poly_modulus_degree();
  const auto plain_mod = params.plain_modulus().value();

  std::cout << "Encoding with poly_mod_degree=" << poly_modulus_degree
            << ", plain_mod = " << plain_mod << std::endl;
  std::cout << "Value = " << value.to_string() << std::endl;

  // TODO: use the correct size for the value given
  destination.resize(poly_modulus_degree);
  destination.set_zero();
  size_t i = 0;
  while (!value.is_zero()) {
    BigUInt r;
    value = value.divrem(plain_mod, r);
    // TODO: check that we don't overflow the polynomial
    destination[i++] = (*r.data());
  }
}

BigUInt PackedBigUIntEncoder::decode(const Plaintext &pt) const {
  const auto params = context_->first_context_data()->parms();
  const auto plain_mod = params.plain_modulus().value();

  BigUInt result;
  for (size_t i = pt.significant_coeff_count(); i > 0; i--) {
    result *= plain_mod;
    result += pt[i - 1];
  }
  return result;
}

}  // namespace pir
