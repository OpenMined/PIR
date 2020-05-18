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
#include "util/canonical_errors.h"
#include "util/statusor.h"

namespace pir {

using ::private_join_and_compute::InvalidArgumentError;
using ::private_join_and_compute::StatusOr;

StatusOr<std::string> serializeEncryptionParams(
    const seal::EncryptionParameters& parms) {
  std::stringstream stream;

  try {
    parms.save(stream);
  } catch (const std::exception& e) {
    return InvalidArgumentError(e.what());
  }
  return stream.str();
}

StatusOr<seal::EncryptionParameters> deserializeEncryptionParams(
    const std::string& input) {
  seal::EncryptionParameters parms;

  std::stringstream stream;
  stream << input;

  try {
    parms.load(stream);
  } catch (const std::exception& e) {
    return InvalidArgumentError(e.what());
  }

  return parms;
}

seal::EncryptionParameters generateEncryptionParams(
    std::optional<uint32_t> poly_mod_opt, std::optional<Modulus> plain_mod_opt,
    std::optional<std::vector<Modulus>> coeff_opt,
    std::optional<seal::scheme_type> scheme_opt) {
  auto poly_modulus_degree = poly_mod_opt.value_or(DEFAULT_POLY_MODULUS_DEGREE);
  auto plain_modulus = plain_mod_opt.value_or(
      seal::PlainModulus::Batching(poly_modulus_degree, 20));
  auto coeff =
      coeff_opt.value_or(seal::CoeffModulus::BFVDefault(poly_modulus_degree));
  auto scheme = scheme_opt.value_or(seal::scheme_type::BFV);
  seal::EncryptionParameters parms(scheme);
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_plain_modulus(plain_modulus);
  parms.set_coeff_modulus(coeff);
  return parms;
}

}  // namespace pir
