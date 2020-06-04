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
#include "pir/cpp/client.h"

#include "absl/memory/memory.h"
#include "pir/cpp/database.h"
#include "pir/cpp/utils.h"
#include "seal/seal.h"
#include "util/canonical_errors.h"
#include "util/status_macros.h"
#include "util/statusor.h"

namespace pir {

using ::private_join_and_compute::InternalError;
using ::private_join_and_compute::InvalidArgumentError;
using ::private_join_and_compute::StatusOr;
using ::seal::Ciphertext;
using ::seal::GaloisKeys;
using ::seal::Plaintext;

PIRClient::PIRClient(std::unique_ptr<PIRContext> context)
    : context_(std::move(context)) {
  auto sealctx = context_->SEALContext();
  keygen_ = std::make_unique<seal::KeyGenerator>(sealctx);
  encryptor_ =
      std::make_shared<seal::Encryptor>(sealctx, keygen_->public_key());
  decryptor_ =
      std::make_shared<seal::Decryptor>(sealctx, keygen_->secret_key());
}

StatusOr<std::unique_ptr<PIRClient>> PIRClient::Create(
    std::shared_ptr<PIRParameters> params) {
  ASSIGN_OR_RETURN(auto context, PIRContext::Create(params));
  return absl::WrapUnique(new PIRClient(std::move(context)));
}

StatusOr<uint64_t> InvertMod(uint64_t m, const seal::Modulus& mod) {
  if (mod.uint64_count() > 1) {
    return InternalError("Modulus too big to invert");
  }
  uint64_t inverse;
  if (!seal::util::try_invert_uint_mod(m, mod.value(), inverse)) {
    return InternalError("Could not invert value");
  }
  return inverse;
}

StatusOr<Request> PIRClient::CreateRequest(std::size_t desired_index) const {
  const auto poly_modulus_degree =
      context_->Parameters()->GetEncryptionParams().poly_modulus_degree();
  if (desired_index >= DBSize()) {
    return InvalidArgumentError("invalid index");
  }

  const auto& plain_mod =
      context_->Parameters()->GetEncryptionParams().plain_modulus();

  auto dims = context_->Parameters()->Dimensions();
  auto indices = PIRDatabase::calculate_indices(dims, desired_index);

  const size_t dim_sum =
      std::accumulate(dims.begin(), dims.end(), decltype(dims)::value_type(0));

  size_t offset = 0;
  vector<Ciphertext> query(dim_sum / poly_modulus_degree + 1);
  for (size_t c = 0; c < query.size(); ++c) {
    Plaintext pt(poly_modulus_degree);
    pt.set_zero();

    while (!indices.empty()) {
      if (indices[0] + offset >= poly_modulus_degree) {
        // no more slots in this poly
        indices[0] -= (poly_modulus_degree - offset);
        dims[0] -= (poly_modulus_degree - offset);
        offset = 0;
        break;
      }
      uint64_t m = (c < query.size() - 1)
                       ? poly_modulus_degree
                       : next_power_two(dim_sum % poly_modulus_degree);
      ASSIGN_OR_RETURN(pt[indices[0] + offset], InvertMod(m, plain_mod));
      offset += dims[0];
      indices.erase(indices.begin());
      dims.erase(dims.begin());

      if (offset >= poly_modulus_degree) {
        offset -= poly_modulus_degree;
        break;
      }
    }

    try {
      encryptor_->encrypt(pt, query[c]);
    } catch (const std::exception& e) {
      return InternalError(e.what());
    }
  }

  GaloisKeys gal_keys;
  try {
    gal_keys =
        keygen_->galois_keys_local(generate_galois_elts(poly_modulus_degree));
  } catch (const std::exception& e) {
    return InternalError(e.what());
  }

  Request request_proto;

  RETURN_IF_ERROR(SaveCiphertexts(query, request_proto.mutable_query()));
  RETURN_IF_ERROR(
      SEALSerialize<GaloisKeys>(gal_keys, request_proto.mutable_keys()));

  return request_proto;
}

StatusOr<int64_t> PIRClient::ProcessResponse(
    const Response& response_proto) const {
  ASSIGN_OR_RETURN(auto response, LoadCiphertexts(context_->SEALContext(),
                                                  response_proto.reply()));
  if (response.size() != 1) {
    return InvalidArgumentError("Number of ciphertexts in response must be 1");
  }
  seal::Plaintext plaintext;
  try {
    decryptor_->decrypt(response[0], plaintext);
    // have to divide the integer result by the the next power of 2 greater than
    // number of items in oblivious expansion.
    return context_->Encoder()->decode_int64(plaintext);
  } catch (const std::exception& e) {
    return InternalError(e.what());
  }
  return InternalError("Should never get here.");
}

}  // namespace pir
