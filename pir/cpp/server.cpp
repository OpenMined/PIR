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
#include "server.h"

#include "absl/memory/memory.h"
#include "payload.h"
#include "seal/seal.h"
#include "seal/util/polyarithsmallmod.h"
#include "util/canonical_errors.h"
#include "util/status_macros.h"
#include "util/statusor.h"

namespace pir {

using ::private_join_and_compute::InvalidArgumentError;
using ::private_join_and_compute::StatusOr;

PIRServer::PIRServer(std::unique_ptr<PIRContext> context,
                     std::shared_ptr<PIRDatabase> db)
    : context_(std::move(context)), db_(db) {}

StatusOr<std::unique_ptr<PIRServer>> PIRServer::Create(
    std::shared_ptr<PIRDatabase> db, std::shared_ptr<PIRParameters> params) {
  if (params->DBSize() != db->size()) {
    return InvalidArgumentError("database size mismatch");
  }
  ASSIGN_OR_RETURN(auto context, PIRContext::Create(params));
  return absl::WrapUnique(new PIRServer(std::move(context), db));
}

StatusOr<std::unique_ptr<PIRServer>> PIRServer::Create(
    std::shared_ptr<PIRDatabase> db) {
  return PIRServer::Create(db, PIRParameters::Create(db->size()));
}

StatusOr<PIRPayload> PIRServer::ProcessRequest(
    const PIRPayload& payload) const {
  if (payload.Get().size() != 1) {
    return InvalidArgumentError("Number of ciphertexts in request must be 1");
  }
  if (!payload.GetKeys()) {
    return InvalidArgumentError("Must have Galois Keys in request");
  }

  auto selection_vector =
      oblivious_expansion(payload.Get()[0], DBSize(), *payload.GetKeys());

  ASSIGN_OR_RETURN(auto mult_results, db_->multiply(selection_vector));

  seal::Ciphertext result;
  context_->Evaluator()->add_many(mult_results, result);

  return PIRPayload::Load(vector<seal::Ciphertext>{result});
}

void PIRServer::substitute_power_x_inplace(
    seal::Ciphertext& ct, uint32_t power,
    const seal::GaloisKeys& gal_keys) const {
  context_->Evaluator()->apply_galois_inplace(ct, power, gal_keys);
}

void PIRServer::multiply_power_of_x(const seal::Ciphertext& encrypted, int k,
                                    seal::Ciphertext& destination) const {
  // This has to get the actual params from the SEALContext. Using just the
  // params from PIR doesn't work.
  const auto& params = context_->SEALContext()->first_context_data()->parms();
  const auto poly_modulus_degree = params.poly_modulus_degree();
  const auto coeff_mod_count = params.coeff_modulus().size();

  // handle negative values of k properly
  uint32_t index = (k >= 0) ? k : (poly_modulus_degree * 2 + k);

  // have to make a copy here
  destination = encrypted;

  // Loop over polynomials in ciphertext
  for (size_t i = 0; i < encrypted.size(); i++) {
    // loop over each coefficient in polynomial
    for (int j = 0; j < coeff_mod_count; j++) {
      seal::util::negacyclic_shift_poly_coeffmod(
          encrypted.data(i) + (j * poly_modulus_degree), poly_modulus_degree,
          index, params.coeff_modulus()[j],
          destination.data(i) + (j * poly_modulus_degree));
    }
  }
}

std::vector<seal::Ciphertext> PIRServer::oblivious_expansion(
    const seal::Ciphertext& ct, const size_t num_items,
    const seal::GaloisKeys& gal_keys) const {
  const auto poly_modulus_degree =
      context_->Parameters()->GetEncryptionParams().poly_modulus_degree();
  size_t logm = ceil_log2(num_items);
  std::vector<seal::Ciphertext> results(next_power_two(num_items));
  results[0] = ct;

  for (size_t j = 0; j < logm; ++j) {
    const size_t two_power_j = (1 << j);
    for (size_t k = 0; k < two_power_j; ++k) {
      auto c0 = results[k];
      seal::Ciphertext c1;
      // TODO: not sure which is faster: substitution operator, or multiply by
      // factor of x? We can do one of them only once depending on order.
      multiply_power_of_x(c0, -two_power_j, c1);

      results[k] = c0;
      substitute_power_x_inplace(c0, (poly_modulus_degree >> j) + 1, gal_keys);
      context_->Evaluator()->add_inplace(results[k], c0);

      results[k + two_power_j] = c1;
      substitute_power_x_inplace(c1, (poly_modulus_degree >> j) + 1, gal_keys);
      context_->Evaluator()->add_inplace(results[k + two_power_j], c1);
    }
  }
  results.resize(num_items);
  return results;
}

}  // namespace pir
