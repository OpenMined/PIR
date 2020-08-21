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
#include "pir/cpp/ct_reencoder.h"
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
    : context_(std::move(context)) {}

Status PIRClient::initialize() {
  ASSIGN_OR_RETURN(db_, PIRDatabase::Create(context_->Params()));
  try {
    auto sealctx = context_->SEALContext();
    keygen_ = std::make_unique<seal::KeyGenerator>(sealctx);
    encryptor_ =
        std::make_shared<seal::Encryptor>(sealctx, keygen_->public_key());
    decryptor_ =
        std::make_shared<seal::Decryptor>(sealctx, keygen_->secret_key());
    auto gal_keys = keygen_->galois_keys(generate_galois_elts(
        context_->EncryptionParams().poly_modulus_degree()));
    auto relin_keys = keygen_->relin_keys();
    request_proto_ = std::make_unique<Request>();
    RETURN_IF_ERROR(
        SEALSerialize<>(gal_keys, request_proto_->mutable_galois_keys()));
    RETURN_IF_ERROR(
        SEALSerialize<>(relin_keys, request_proto_->mutable_relin_keys()));
  } catch (const std::exception& ex) {
    return InternalError(ex.what());
  }
  return Status::OK;
}

StatusOr<std::unique_ptr<PIRClient>> PIRClient::Create(
    shared_ptr<PIRParameters> params) {
  ASSIGN_OR_RETURN(auto context, PIRContext::Create(params));
  auto client = absl::WrapUnique(new PIRClient(std::move(context)));
  RETURN_IF_ERROR(client->initialize());
  return client;
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
  vector<vector<Ciphertext>> queries(indexes.size());
  for (size_t i = 0; i < indexes.size(); ++i) {
    RETURN_IF_ERROR(createQueryFor(indexes[i], queries[i]));
  }

  Request request_proto(*request_proto_);
  RETURN_IF_ERROR(SaveRequest(queries, &request_proto));
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

  auto dims = std::vector<uint32_t>(context_->Params()->dimensions().begin(),
                                    context_->Params()->dimensions().end());
  auto indices = db_->calculate_indices(desired_index);

  const size_t dim_sum = context_->DimensionsSum();

  size_t offset = 0;
  query.resize(dim_sum / poly_modulus_degree + 1);
  Plaintext pt(poly_modulus_degree);
  for (size_t c = 0; c < query.size(); ++c) {
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
    ASSIGN_OR_RETURN(auto result_pt, ProcessReply(r));
    try {
      result.push_back(context_->Encoder()->decode_int64(result_pt));
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

  StringEncoder encoder(context_->SEALContext());
  if (context_->Params()->bits_per_coeff() > 0) {
    encoder.set_bits_per_coeff(context_->Params()->bits_per_coeff());
  }
  vector<string> result;
  result.reserve(response_proto.reply_size());

  for (size_t i = 0; i < indexes.size(); ++i) {
    ASSIGN_OR_RETURN(auto result_pt, ProcessReply(response_proto.reply(i)));

    ASSIGN_OR_RETURN(
        auto v, encoder.decode(result_pt, context_->Params()->bytes_per_item(),
                               db_->calculate_item_offset(indexes[i])));
    result.push_back(v);
  }
  return result;
}

StatusOr<Plaintext> PIRClient::ProcessReply(
    const Ciphertexts& reply_proto) const {
  if (context_->Params()->use_ciphertext_multiplication()) {
    return ProcessReplyCiphertextMult(reply_proto);
  } else {
    return ProcessReplyCiphertextDecomp(reply_proto);
  }
}

StatusOr<Plaintext> PIRClient::ProcessReplyCiphertextMult(
    const Ciphertexts& reply_proto) const {
  ASSIGN_OR_RETURN(auto reply_cts,
                   LoadCiphertexts(context_->SEALContext(), reply_proto));
  if (reply_cts.size() != 1) {
    return InvalidArgumentError(
        "Number of ciphertexts in reply must be 1 when using CT "
        "multiplication");
  }

  const auto poly_modulus_degree =
      context_->EncryptionParams().poly_modulus_degree();
  seal::Plaintext pt(poly_modulus_degree, 0);

  try {
    decryptor_->decrypt(reply_cts[0], pt);
  } catch (const std::exception& e) {
    return InternalError(e.what());
  }

  return pt;
}

StatusOr<Plaintext> PIRClient::ProcessReplyCiphertextDecomp(
    const Ciphertexts& reply_proto) const {
  ASSIGN_OR_RETURN(auto ct_reencoder,
                   CiphertextReencoder::Create(context_->SEALContext()));
  // TODO: this should use the original CT size
  const size_t exp_ratio = ct_reencoder->ExpansionRatio() * 2;
  const size_t num_dims = context_->Params()->dimensions_size();
  const size_t num_ct_per_reply = ipow(exp_ratio, num_dims - 1);

  ASSIGN_OR_RETURN(auto reply_cts,
                   LoadCiphertexts(context_->SEALContext(), reply_proto));
  if (reply_cts.size() != num_ct_per_reply) {
    return InvalidArgumentError(
        "Number of ciphertexts in reply does not match expected");
  }
  vector<Plaintext> reply_pts;

  for (size_t d = 0; d < num_dims; ++d) {
    reply_pts.resize(reply_cts.size());
    try {
      for (size_t i = 0; i < reply_cts.size(); ++i) {
        decryptor_->decrypt(reply_cts[i], reply_pts[i]);
      }
    } catch (const std::exception& e) {
      return InternalError(e.what());
    }

    if (reply_pts.size() <= 1) break;

    reply_cts.resize(reply_cts.size() / exp_ratio);
    for (size_t i = 0; i < reply_cts.size(); ++i) {
      reply_cts[i] = ct_reencoder->Decode(reply_pts.begin() + i * exp_ratio, 2);
    }
  }

  return reply_pts[0];
}
}  // namespace pir
