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
#include "pir/cpp/server.h"

#include "pir/cpp/status_asserts.h"
#include "pir/cpp/utils.h"
#include "seal/seal.h"
#include "seal/util/polyarithsmallmod.h"

namespace pir {

using absl::Status;
using absl::StatusOr;
using ::seal::GaloisKeys;
using ::seal::RelinKeys;
using ::std::shared_ptr;

PIRServer::PIRServer(std::unique_ptr<PIRContext> context,
                     std::shared_ptr<PIRDatabase> db)
    : context_(std::move(context)), db_(db) {}

StatusOr<std::unique_ptr<PIRServer>> PIRServer::Create(
    std::shared_ptr<PIRDatabase> db, shared_ptr<PIRParameters> params) {
  if (params->num_pt() != db->size()) {
    return absl::InvalidArgumentError("database size mismatch");
  }
  ASSIGN_OR_RETURN(auto context, PIRContext::Create(params));
  return absl::WrapUnique(new PIRServer(std::move(context), db));
}

StatusOr<Response> PIRServer::ProcessRequest(const Request& request) const {
  Response response;
  ASSIGN_OR_RETURN(auto galois_keys,
                   SEALDeserialize<GaloisKeys>(context_->SEALContext(),
                                               request.galois_keys()));

  const auto dimensions = context_->Params()->dimensions();
  const size_t dim_sum = context_->DimensionsSum();

  optional<RelinKeys> relin_keys;
  if (!request.relin_keys().empty()) {
    ASSIGN_OR_RETURN(relin_keys,
                     SEALDeserialize<RelinKeys>(context_->SEALContext(),
                                                request.relin_keys()));
  }

  for (const auto& query : request.query()) {
    RETURN_IF_ERROR(processQuery(query, galois_keys, relin_keys, dim_sum,
                                 response.add_reply()));
  }
  return response;
}

Status PIRServer::substitute_power_x_inplace(
    seal::Ciphertext& ct, uint32_t power,
    const seal::GaloisKeys& gal_keys) const {
  try {
    context_->Evaluator()->apply_galois_inplace(ct, power, gal_keys);
  } catch (const std::exception& e) {
    return absl::InternalError(e.what());
  }
  return absl::OkStatus();
}

void PIRServer::multiply_inverse_power_of_x(
    const seal::Ciphertext& encrypted, uint32_t k,
    seal::Ciphertext& destination) const {
  // This has to get the actual params from the SEALContext. Using just the
  // params from PIR doesn't work.
  const auto& params = context_->SEALContext()->first_context_data()->parms();
  const auto poly_modulus_degree = params.poly_modulus_degree();
  const auto coeff_mod_count = params.coeff_modulus().size();

  uint32_t index =
      ((poly_modulus_degree << 1) - k) % (poly_modulus_degree << 1);

  // have to make a copy here
  destination = encrypted;

  // Loop over polynomials in ciphertext
  for (size_t i = 0; i < encrypted.size(); i++) {
    // loop over each coefficient in polynomial
    for (size_t j = 0; j < coeff_mod_count; j++) {
      seal::util::negacyclic_shift_poly_coeffmod(
          encrypted.data(i) + (j * poly_modulus_degree), poly_modulus_degree,
          index, params.coeff_modulus()[j],
          destination.data(i) + (j * poly_modulus_degree));
    }
  }
}

StatusOr<std::vector<seal::Ciphertext>> PIRServer::oblivious_expansion(
    const seal::Ciphertext& ct, const size_t num_items,
    const seal::GaloisKeys& gal_keys) const {
  const auto poly_modulus_degree =
      context_->EncryptionParams().poly_modulus_degree();

  if (num_items > poly_modulus_degree) {
    return absl::InvalidArgumentError(
        "Cannot expand more items from a CT than poly modulus degree");
  }

  size_t logm = ceil_log2(num_items);
  std::vector<seal::Ciphertext> results(next_power_two(num_items));
  results[0] = ct;

  for (size_t j = 0; j < logm; ++j) {
    const size_t two_power_j = (1 << j);
    for (size_t k = 0; k < two_power_j; ++k) {
      auto c0 = results[k];

      RETURN_IF_ERROR(substitute_power_x_inplace(
          c0, (poly_modulus_degree >> j) + 1, gal_keys));

      // This essentially produces what the paper calls c1
      multiply_inverse_power_of_x(results[k], two_power_j,
                                  results[k + two_power_j]);

      // Do the multiply by power of x after substitution operator to avoid
      // having to do the substitution operator a second time, since it's about
      // 20x slower. Except that now instead of multiplying by x^(-2^j) we have
      // to do the substitution first ourselves, producing
      // (x^(N/2^j + 1))^(-2^j) = 1/x^(2^j * (N/2^j + 1)) = 1/x^(N + 2^j)
      seal::Ciphertext c1;
      multiply_inverse_power_of_x(c0, poly_modulus_degree + two_power_j, c1);

      context_->Evaluator()->add_inplace(results[k], c0);
      context_->Evaluator()->add_inplace(results[k + two_power_j], c1);
    }
  }
  results.resize(num_items);
  return results;
}

StatusOr<std::vector<seal::Ciphertext>> PIRServer::oblivious_expansion(
    const std::vector<seal::Ciphertext>& cts, size_t total_items,
    const seal::GaloisKeys& gal_keys) const {
  size_t poly_modulus_degree =
      context_->EncryptionParams().poly_modulus_degree();

  if (cts.size() != total_items / poly_modulus_degree + 1) {
    return absl::InvalidArgumentError(
        "Number of ciphertexts doesn't match number of items for oblivious "
        "expansion.");
  }

  std::vector<seal::Ciphertext> results;
  results.reserve(total_items);
  for (const auto& ct : cts) {
    ASSIGN_OR_RETURN(
        auto v, oblivious_expansion(
                    ct, std::min(poly_modulus_degree, total_items), gal_keys));
    results.insert(results.end(), std::make_move_iterator(v.begin()),
                   std::make_move_iterator(v.end()));
    total_items -= poly_modulus_degree;
  }
  return results;
}

Status PIRServer::processQuery(const Ciphertexts& query_proto,
                               const GaloisKeys& galois_keys,
                               const optional<RelinKeys>& relin_keys,
                               const size_t& dim_sum,
                               Ciphertexts* output) const {
  ASSIGN_OR_RETURN(auto query,
                   LoadCiphertexts(context_->SEALContext(), query_proto));

  ASSIGN_OR_RETURN(auto selection_vector,
                   oblivious_expansion(query, dim_sum, galois_keys));

  vector<seal::Ciphertext> results;
  if (relin_keys) {
    ASSIGN_OR_RETURN(results,
                     db_->multiply(selection_vector, &relin_keys.value()));
  } else {
    ASSIGN_OR_RETURN(results, db_->multiply(selection_vector));
  }

  RETURN_IF_ERROR(SaveCiphertexts(results, output));

  return absl::OkStatus();
}

}  // namespace pir
