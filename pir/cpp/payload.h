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

#ifndef PIR_PAYLOAD_H_
#define PIR_PAYLOAD_H_

#include <string>

#include "pir/proto/payload.pb.h"
#include "seal/seal.h"
#include "util/canonical_errors.h"
#include "util/status_macros.h"
#include "util/statusor.h"

namespace pir {

using ::private_join_and_compute::InternalError;
using ::private_join_and_compute::InvalidArgumentError;
using ::private_join_and_compute::StatusOr;

/**
 * Decodes and loads a PIR Ciphertext.
 * @param[in] The SEAL context, for buffer allocations.
 * @param[in] The encoded ciphertext.
 * @returns InvalidArgument if the decoding fails.
 **/
StatusOr<std::vector<seal::Ciphertext>> LoadCiphertexts(
    const std::shared_ptr<seal::SEALContext>& ctx, const Ciphertexts& encoded);
/**
 * Saves the Ciphertexts to a protobuffer.
 * @returns InvalidArgument if the encoding fails
 **/
StatusOr<Ciphertexts> SaveCiphertexts(
    const std::vector<seal::Ciphertext>& buff);

/**
 * Saves a SEAL object to a string.
 * Compatible SEAL types: Ciphertext, Plaintext, SecretKey, PublicKey,
 *GaloisKeys, RelinKeys.
 * @returns InternalError if the encoding fails.
 **/
template <class T>
StatusOr<std::string> SEALSerialize(const T& sealobj) {
  std::stringstream stream;

  try {
    sealobj.save(stream);
  } catch (const std::exception& e) {
    return InternalError(e.what());
  }

  return stream.str();
}

/**
 * Loads a SEAL object from a string.
 * Compatible SEAL types: Ciphertext, Plaintext, SecretKey, PublicKey,
 *GaloisKeys, RelinKeys.
 * @returns InvalidArgument if the decoding fails.
 **/
template <class T>
StatusOr<T> SEALDeserialize(const std::shared_ptr<seal::SEALContext>& sealctx,
                            const std::string& in) {
  T out;

  try {
    std::stringstream stream;
    stream << in;
    out.load(sealctx, stream);
  } catch (const std::exception& e) {
    return InvalidArgumentError(e.what());
  }

  return out;
}
}  // namespace pir

#endif  // PIR_PAYLOAD_H_
