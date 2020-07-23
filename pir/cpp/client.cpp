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
#include "pir/cpp/string_encoder.h"
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
using ::seal::RelinKeys;

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
    shared_ptr<PIRParameters> params) {
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

StatusOr<Request> PIRClient::CreateRequest(
    const std::vector<std::size_t>& indexes) const {
  const auto poly_modulus_degree =
      context_->EncryptionParams().poly_modulus_degree();

  vector<vector<Ciphertext>> queries(indexes.size());

  for (size_t i = 0; i < indexes.size(); ++i) {
    RETURN_IF_ERROR(createQueryFor(indexes[i], queries[i]));
  }

  GaloisKeys gal_keys;
  RelinKeys relin_keys;
  try {
    gal_keys =
        keygen_->galois_keys_local(generate_galois_elts(poly_modulus_degree));
    relin_keys = keygen_->relin_keys_local();
  } catch (const std::exception& e) {
    return InternalError(e.what());
  }

  Request request_proto;
  RETURN_IF_ERROR(SaveRequest(queries, gal_keys, relin_keys, &request_proto));

  return request_proto;
}

Status PIRClient::createQueryFor(size_t desired_index,
                                 vector<Ciphertext>& query) const {
  if (desired_index >= context_->Params()->num_items()) {
    return InvalidArgumentError("invalid index " +
                                std::to_string(desired_index));
  }
  auto plain_mod = context_->EncryptionParams().plain_modulus();
  const auto poly_modulus_degree =
      context_->EncryptionParams().poly_modulus_degree();

  ASSIGN_OR_RETURN(auto pirdb, PIRDatabase::Create(context_->Params()));
  auto dims = std::vector<uint32_t>(context_->Params()->dimensions().begin(),
                                    context_->Params()->dimensions().end());
  auto indices = pirdb->calculate_indices(desired_index);

  const size_t dim_sum = context_->DimensionsSum();

  size_t offset = 0;
  query.resize(dim_sum / poly_modulus_degree + 1);
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

  return Status::OK;
}

StatusOr<std::vector<int64_t>> PIRClient::ProcessResponseInteger(
    const Response& response_proto) const {
  vector<int64_t> result;
  result.reserve(response_proto.reply_size());
  for (const auto& r : response_proto.reply()) {
    ASSIGN_OR_RETURN(auto reply, LoadCiphertexts(context_->SEALContext(), r));
    if (reply.size() != 1) {
      return InvalidArgumentError("Number of ciphertexts in reply must be 1");
    }
    seal::Plaintext plaintext;
    try {
      decryptor_->decrypt(reply[0], plaintext);
      result.push_back(context_->Encoder()->decode_int64(plaintext));
    } catch (const std::exception& e) {
      return InternalError(e.what());
    }
  }
  return result;
}

StatusOr<std::vector<string>> PIRClient::ProcessResponse(
    const std::vector<std::size_t>& indexes,
    const Response& response_proto) const {
  if (indexes.size() != response_proto.reply_size()) {
    return InvalidArgumentError(
        "Number of indexes must match number of replies");
  }

  ASSIGN_OR_RETURN(auto pirdb, PIRDatabase::Create(context_->Params()));
  StringEncoder encoder(context_->SEALContext());
  if (context_->Params()->bits_per_coeff() > 0) {
    encoder.set_bits_per_coeff(context_->Params()->bits_per_coeff());
  }
  vector<string> result;
  result.reserve(response_proto.reply_size());
  for (size_t i = 0; i < indexes.size(); ++i) {
    ASSIGN_OR_RETURN(auto reply, LoadCiphertexts(context_->SEALContext(),
                                                 response_proto.reply(i)));
    if (reply.size() != 1) {
      return InvalidArgumentError("Number of ciphertexts in reply must be 1");
    }
    seal::Plaintext plaintext;
    try {
      decryptor_->decrypt(reply[0], plaintext);
    } catch (const std::exception& e) {
      return InternalError(e.what());
    }
    ASSIGN_OR_RETURN(
        auto v, encoder.decode(plaintext, context_->Params()->bytes_per_item(),
                               pirdb->calculate_item_offset(indexes[i])));
    result.push_back(v);
  }
  return result;
}
}  // namespace pir
