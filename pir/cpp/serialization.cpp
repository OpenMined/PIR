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
#include "pir/cpp/serialization.h"

#include "pir/cpp/status_asserts.h"
#include "pir/cpp/utils.h"
#include "seal/seal.h"

namespace pir {

using absl::InvalidArgumentError;
using absl::StatusOr;
using seal::Ciphertext;
using seal::GaloisKeys;
using seal::RelinKeys;
using std::string;
using std::vector;

StatusOr<vector<Ciphertext>> LoadCiphertexts(
    const std::shared_ptr<seal::SEALContext>& sealctx,
    const Ciphertexts& input) {
  vector<Ciphertext> output(input.ct_size());
  for (int idx = 0; idx < input.ct_size(); ++idx) {
    ASSIGN_OR_RETURN(output[idx],
                     SEALDeserialize<Ciphertext>(sealctx, input.ct(idx)));
  }

  return output;
}

Status SaveCiphertexts(const vector<Ciphertext>& ciphertexts,
                       Ciphertexts* output) {
  if (output == nullptr) {
    return InvalidArgumentError("output nullptr");
  }

  for (size_t idx = 0; idx < ciphertexts.size(); ++idx) {
    RETURN_IF_ERROR(
        SEALSerialize<Ciphertext>(ciphertexts[idx], output->add_ct()));
  }
  return absl::OkStatus();
}

Status SaveRequest(const vector<vector<Ciphertext>>& cts, Request* request) {
  for (const auto& ct : cts) {
    RETURN_IF_ERROR(SaveCiphertexts(ct, request->add_query()));
  }
  return absl::OkStatus();
}

Status SaveRequest(const vector<vector<Ciphertext>>& cts,
                   const seal::GaloisKeys& galois_keys,
                   const seal::RelinKeys& relin_keys, Request* request) {
  RETURN_IF_ERROR(SaveRequest(cts, request));
  RETURN_IF_ERROR(
      SEALSerialize<GaloisKeys>(galois_keys, request->mutable_galois_keys()));
  RETURN_IF_ERROR(
      SEALSerialize<RelinKeys>(relin_keys, request->mutable_relin_keys()));
  return absl::OkStatus();
}

};  // namespace pir
