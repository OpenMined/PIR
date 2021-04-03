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

#include "pir/cpp/database.h"
#include "pir/cpp/serialization.h"
#include "pir/cpp/status_asserts.h"
#include "pir/cpp/string_encoder.h"
#include "pir/cpp/utils.h"
#include "seal/seal.h"

namespace pir {

using absl::InvalidArgumentError;
using absl::StatusOr;
using ::seal::EncryptionParameters;
using ::std::make_shared;
using ::std::shared_ptr;

EncryptionParameters GenerateEncryptionParams(uint32_t poly_mod_degree,
                                              uint32_t plain_mod_bit_size) {
  return GenerateEncryptionParams(
      poly_mod_degree,
      seal::PlainModulus::Batching(poly_mod_degree, plain_mod_bit_size));
}

EncryptionParameters GenerateEncryptionParams(
    std::optional<uint32_t> poly_mod_opt, std::optional<Modulus> plain_mod_opt,
    std::optional<std::vector<Modulus>> coeff_opt) {
  auto poly_modulus_degree = poly_mod_opt.value_or(DEFAULT_POLY_MODULUS_DEGREE);
  auto plain_modulus = plain_mod_opt.value_or(
      seal::PlainModulus::Batching(poly_modulus_degree, 20));
  auto coeff =
      coeff_opt.value_or(seal::CoeffModulus::BFVDefault(poly_modulus_degree));

  EncryptionParameters parms(seal::scheme_type::BFV);
  parms.set_poly_modulus_degree(poly_modulus_degree);
  parms.set_plain_modulus(plain_modulus);
  parms.set_coeff_modulus(coeff);
  return parms;
}

StatusOr<shared_ptr<PIRParameters>> CreatePIRParameters(
    size_t dbsize, size_t bytes_per_item, size_t dimensions,
    EncryptionParameters seal_params, bool use_ciphertext_multiplication,
    size_t bits_per_coeff) {
  // Make sure SEAL Parameter are valid
  auto seal_context = seal::SEALContext::Create(seal_params);
  if (!seal_context->parameters_set()) {
    return InvalidArgumentError(
        string("Error setting encryption parameters: ") +
        seal_context->parameter_error_message());
  }
  StringEncoder encoder(seal_context);

  auto parameters = std::make_shared<PIRParameters>();
  parameters->set_num_items(dbsize);
  parameters->set_use_ciphertext_multiplication(use_ciphertext_multiplication);

  if (bits_per_coeff > 0) {
    if (bits_per_coeff > encoder.bits_per_coeff()) {
      return InvalidArgumentError("Bits per coefficient greater than max");
    }
    encoder.set_bits_per_coeff(bits_per_coeff);
    parameters->set_bits_per_coeff(bits_per_coeff);
  }

  if (bytes_per_item > 0) {
    parameters->set_bytes_per_item(bytes_per_item);
    parameters->set_items_per_plaintext(
        encoder.num_items_per_plaintext(bytes_per_item));
    if (parameters->items_per_plaintext() <= 0) {
      return InvalidArgumentError("Cannot fit an item within one plaintext");
    }
    size_t num_pt = dbsize / parameters->items_per_plaintext();
    while (dbsize > num_pt * parameters->items_per_plaintext()) {
      ++num_pt;
    }
    parameters->set_num_pt(num_pt);
  } else {
    parameters->set_bytes_per_item(encoder.max_bytes_per_plaintext());
    parameters->set_items_per_plaintext(1);
    parameters->set_num_pt(dbsize);
  }

  RETURN_IF_ERROR(SEALSerialize<EncryptionParameters>(
      seal_params, parameters->mutable_encryption_parameters()));

  for (auto& dim :
       PIRDatabase::calculate_dimensions(parameters->num_pt(), dimensions))
    parameters->add_dimensions(dim);

  return parameters;
}

}  // namespace pir
