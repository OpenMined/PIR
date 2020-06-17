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

namespace pir {

StringEncoder::StringEncoder(shared_ptr<seal::SEALContext> context)
    : context_(context) {
  const auto params = context_->first_context_data()->parms();
  poly_modulus_degree_ = params.poly_modulus_degree();
  bits_per_coeff_ = log2(params.plain_modulus().value());
}

void StringEncoder::encode(const string& value, Plaintext& destination) const {
  size_t num_coeff =
      ceil(static_cast<double>(value.size() * 8) / bits_per_coeff_);
  // TODO: check if num_coeff < poly_mod_degree
  destination.resize(num_coeff);
  destination.set_zero();
  size_t coeff_index = 0;
  size_t coeff_bits = bits_per_coeff_;
  for (uint8_t c : value) {
    size_t remain_bits = 8;
    while (remain_bits > 0) {
      size_t n = std::min(coeff_bits, remain_bits);
      destination[coeff_index] <<= n;
      destination[coeff_index] |= (c >> (8 - n));
      c <<= n;
      coeff_bits -= n;
      remain_bits -= n;
      if (coeff_bits <= 0) {
        ++coeff_index;
        coeff_bits = bits_per_coeff_;
      }
    }
  }
  destination[coeff_index] <<= coeff_bits;
}

string StringEncoder::decode(const Plaintext& pt) const {
  const size_t num_bytes = pt.significant_coeff_count() * bits_per_coeff_ / 8;
  string result(num_bytes, 0);
  size_t result_index = 0;
  size_t remain_bits = 8;
  for (size_t i = 0; i < pt.coeff_count(); ++i) {
    size_t coeff_bits = bits_per_coeff_;
    while (coeff_bits > 0) {
      size_t n = std::min(coeff_bits, remain_bits);
      result[result_index] <<= n;
      result[result_index] |= (pt[i] >> (coeff_bits - n));

      coeff_bits -= n;
      remain_bits -= n;
      if (remain_bits <= 0) {
        ++result_index;
        remain_bits = 8;
      }
    }
  }
  return result;
}

}  // namespace pir
