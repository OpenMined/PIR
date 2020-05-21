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
#include "client.h"

#include "absl/memory/memory.h"
#include "seal/seal.h"
#include "util/canonical_errors.h"
#include "util/status_macros.h"
#include "util/statusor.h"

namespace pir {

using ::private_join_and_compute::InternalError;
using ::private_join_and_compute::InvalidArgumentError;
using ::private_join_and_compute::StatusOr;
using seal::Ciphertext;
using seal::Plaintext;

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

StatusOr<PIRPayload> PIRClient::CreateRequest(std::size_t index) const {
  const auto poly_modulus_degree =
      context_->Parameters()->GetEncryptionParams().poly_modulus_degree();
  if (index >= DBSize()) {
    return InvalidArgumentError("invalid index");
  }
  if (index >= poly_modulus_degree) {
    // Not yet implemented
    return InvalidArgumentError("More than 1 CT needed for selection vector");
  }
  Plaintext pt(poly_modulus_degree);
  pt.set_zero();
  pt[index] = 1;
  std::cout << "Query PT: " << pt.to_string() << std::endl;

  vector<Ciphertext> query(1);
  try {
    encryptor_->encrypt(pt, query[0]);
  } catch (const std::exception& e) {
    return InternalError(e.what());
  }
  auto gal_keys =
      keygen_->galois_keys_local(generate_galois_elts(poly_modulus_degree));
  return PIRPayload::Load(query, gal_keys);
}

StatusOr<int64_t> PIRClient::ProcessResponse(const PIRPayload& response) const {
  if (response.Get().size() != 1) {
    return InvalidArgumentError("Number of ciphertexts in response must be 1");
  }
  const uint32_t m = next_power_two(DBSize());

  seal::Plaintext plaintext;
  try {
    decryptor_->decrypt(response.Get()[0], plaintext);
    // have to divide the integer result by the the next power of 2 greater than
    // number of items in oblivious expansion.
    return context_->Encoder()->decode_int64(plaintext) / m;
  } catch (const std::exception& e) {
    return InternalError(e.what());
  }
  return InternalError("Should never get here.");
}

vector<uint32_t> generate_galois_elts(uint64_t N) {
  const size_t logN = ceil(log2(N));
  vector<uint32_t> galois_elts(logN);
  for (size_t i = 0; i < logN; ++i) {
    uint64_t two_exp_i = ((uint64_t)1) << i;
    galois_elts[i] = (N / two_exp_i) + 1;
  }
  return galois_elts;
}

}  // namespace pir
