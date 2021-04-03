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

#include "pir/cpp/serialization.h"
#include "pir/cpp/status_asserts.h"
#include "seal/seal.h"

namespace pir {

StatusOr<std::unique_ptr<CiphertextReencoder>> CiphertextReencoder::Create(
    shared_ptr<SEALContext> context) {
  return absl::WrapUnique(new CiphertextReencoder(context));
}

uint32_t CiphertextReencoder::ExpansionRatio() const {
  uint32_t expansion_ratio = 0;
  const auto params = context_->first_context_data()->parms();
  uint32_t pt_bits_per_coeff = log2(params.plain_modulus().value());
  for (size_t i = 0; i < params.coeff_modulus().size(); ++i) {
    double coeff_bit_size = log2(params.coeff_modulus()[i].value());
    expansion_ratio += ceil(coeff_bit_size / pt_bits_per_coeff);
  }
  return expansion_ratio;
}

vector<Plaintext> CiphertextReencoder::Encode(const Ciphertext& ct) {
  const auto params = context_->first_context_data()->parms();
  const uint32_t pt_bits_per_coeff = log2(params.plain_modulus().value());
  const auto coeff_count = params.poly_modulus_degree();
  const auto coeff_mod_count = params.coeff_modulus().size();
  const uint64_t pt_bitmask = (1 << pt_bits_per_coeff) - 1;

  vector<Plaintext> result(ExpansionRatio() * ct.size());
  auto pt_iter = result.begin();
  for (size_t poly_index = 0; poly_index < ct.size(); ++poly_index) {
    for (size_t coeff_mod_index = 0; coeff_mod_index < coeff_mod_count;
         ++coeff_mod_index) {
      const double coeff_bit_size =
          log2(params.coeff_modulus()[coeff_mod_index].value());
      const size_t local_expansion_ratio =
          ceil(coeff_bit_size / pt_bits_per_coeff);
      size_t shift = 0;
      for (size_t i = 0; i < local_expansion_ratio; ++i) {
        pt_iter->resize(coeff_count);
        for (size_t c = 0; c < coeff_count; ++c) {
          (*pt_iter)[c] =
              (ct.data(poly_index)[coeff_mod_index * coeff_count + c] >>
               shift) &
              pt_bitmask;
        }
        ++pt_iter;
        shift += pt_bits_per_coeff;
      }
    }
  }
  return result;
}

Ciphertext CiphertextReencoder::Decode(const vector<Plaintext>& pts) {
  return Decode(pts.begin(), pts.size() / ExpansionRatio());
}

Ciphertext CiphertextReencoder::Decode(
    vector<Plaintext>::const_iterator pt_iter, const size_t ct_poly_count) {
  const auto params = context_->first_context_data()->parms();
  const uint32_t pt_bits_per_coeff = log2(params.plain_modulus().value());
  const auto coeff_count = params.poly_modulus_degree();
  const auto coeff_mod_count = params.coeff_modulus().size();
  // size_t pt_count = 0;
  // TODO: should check here if numbers match

  Ciphertext ct(context_);
  ct.resize(ct_poly_count);
  for (size_t poly_index = 0; poly_index < ct_poly_count; ++poly_index) {
    for (size_t coeff_mod_index = 0; coeff_mod_index < coeff_mod_count;
         ++coeff_mod_index) {
      const double coeff_bit_size =
          log2(params.coeff_modulus()[coeff_mod_index].value());
      const size_t local_expansion_ratio =
          ceil(coeff_bit_size / pt_bits_per_coeff);
      size_t shift = 0;
      for (size_t i = 0; i < local_expansion_ratio; ++i) {
        for (size_t c = 0; c < pt_iter->coeff_count(); ++c) {
          if (shift == 0) {
            ct.data(poly_index)[coeff_mod_index * coeff_count + c] =
                (*pt_iter)[c];
          } else {
            ct.data(poly_index)[coeff_mod_index * coeff_count + c] +=
                ((*pt_iter)[c] << shift);
          }
        }
        ++pt_iter;
        shift += pt_bits_per_coeff;
      }
    }
  }
  return ct;
}

}  // namespace pir
