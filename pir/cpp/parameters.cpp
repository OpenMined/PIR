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
#include "pir/cpp/parameters.h"

#include "seal/seal.h"
#include "util/canonical_errors.h"
#include "util/statusor.h"

namespace pir {

using ::private_join_and_compute::InvalidArgumentError;
using ::private_join_and_compute::StatusOr;

HEParameters GenerateHEParams(std::optional<uint32_t> poly_mod_opt,
                              std::optional<Modulus> plain_mod_opt,
                              std::optional<std::vector<Modulus>> coeff_opt,
                              std::optional<seal::scheme_type> scheme_opt) {
  auto poly_modulus_degree = poly_mod_opt.value_or(DEFAULT_POLY_MODULUS_DEGREE);
  auto plain_modulus = plain_mod_opt.value_or(
      seal::PlainModulus::Batching(poly_modulus_degree, 20));
  auto coeff =
      coeff_opt.value_or(seal::CoeffModulus::BFVDefault(poly_modulus_degree));
  auto scheme = scheme_opt.value_or(seal::scheme_type::BFV);

  HEParameters parms;
  parms.set_scheme(static_cast<uint32_t>(scheme));
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_plain_modulus(plain_modulus.value());
  for (auto& v : coeff) parms.add_coeff_modulus(v.value());
  return parms;
}

seal::EncryptionParameters GenerateEncryptionParams(
    const HEParameters& he_params) {
  seal::EncryptionParameters parms(he_params.scheme());
  parms.set_poly_modulus_degree(he_params.poly_modulus_degree());
  parms.set_plain_modulus(he_params.plain_modulus());
  parms.set_coeff_modulus(vector<Modulus>(he_params.coeff_modulus().begin(),
                                          he_params.coeff_modulus().end()));
  return parms;
}

Parameters CreatePIRParameters(size_t dbsize, size_t dimensions,
                               HEParameters heParams) {
  Parameters parameters;
  parameters.set_database_size(dbsize);
  *parameters.mutable_he_parameters() = heParams;
  for (auto& dim : CalculateDimensions(dbsize, dimensions))
    parameters.add_dimensions(dim);

  return parameters;
}

std::vector<uint32_t> CalculateDimensions(uint32_t db_size,
                                          uint32_t num_dimensions) {
  std::vector<uint32_t> results;
  for (int i = num_dimensions; i > 0; --i) {
    results.push_back(std::ceil(std::pow(db_size, 1.0 / i)));
    db_size = std::ceil(static_cast<double>(db_size) / results.back());
  }
  return results;
}

}  // namespace pir
