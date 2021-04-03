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

#ifndef PIR_SERIALIZATION_H_
#define PIR_SERIALIZATION_H_

#include <string>

#include "absl/status/statusor.h"
#include "pir/proto/payload.pb.h"
#include "seal/seal.h"

namespace pir {

using absl::InternalError;
using absl::InvalidArgumentError;
using absl::Status;
using absl::StatusOr;
using seal::Ciphertext;
using seal::SEALContext;
using std::shared_ptr;
using std::string;
using std::vector;

/**
 * Decodes and loads a PIR Ciphertext.
 * @param[in] The SEAL context, for buffer allocations.
 * @param[in] The encoded ciphertext.
 * @returns InvalidArgument if the decoding fails.
 **/
StatusOr<vector<Ciphertext>> LoadCiphertexts(const shared_ptr<SEALContext>& ctx,
                                             const Ciphertexts& encoded);

/**
 * Saves the Ciphertexts to a protobuffer.
 * @returns InvalidArgument if the encoding fails
 **/
Status SaveCiphertexts(const vector<Ciphertext>& buff, Ciphertexts* output);

/**
 * Shortcut to save response data to a protocol buffer based on a list of
 * Ciphertexts. It is assumed that Galois keys will be added elsewhere.
 * @param[in] cts The list of Ciphertexts in the query.
 * @param[out] request Point to the request protocol buffer to fill in.
 * @returns InvalidArgument if the encoding fails.
 */
Status SaveRequest(const vector<vector<Ciphertext>>& cts, Request* request);

/**
 * Shortcut to save response data to a protocol buffer based on a list of
 * Ciphertexts, a set of GaloisKeys, and a set or relinearization keys.
 * @param[in] cts The list of Ciphertexts in the query.
 * @param[in] galois_keys The Galois Keys to encode in the protocol buffer.
 * @param[in] relin_keys The relinearization keys to encode.
 * @param[out] request Point to the request protocol buffer to fill in.
 * @returns InvalidArgument if the encoding fails.
 */
Status SaveRequest(const vector<vector<Ciphertext>>& cts,
                   const seal::GaloisKeys& galois_keys,
                   const seal::RelinKeys& relin_keys, Request* request);

/**
 * Saves a SEAL object to a string.
 * Compatible SEAL types: Ciphertext, Plaintext, SecretKey, PublicKey,
 *GaloisKeys, RelinKeys.
 * @returns InternalError if the encoding fails.
 **/
template <class T>
Status SEALSerialize(const T& sealobj, string* output) {
  if (output == nullptr) {
    return InvalidArgumentError("output nullptr");
  }
  std::stringstream stream;

  try {
    sealobj.save(stream);
  } catch (const std::exception& e) {
    return InternalError(e.what());
  }

  *output = stream.str();
  return absl::OkStatus();
}

/**
 * Loads a SEAL object from a string.
 * Compatible SEAL types: Ciphertext, Plaintext, SecretKey, PublicKey,
 *GaloisKeys, RelinKeys.
 * @returns InvalidArgument if the decoding fails.
 **/
template <class T>
StatusOr<T> SEALDeserialize(const shared_ptr<SEALContext>& sealctx,
                            const string& in) {
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

/**
 * Loads a SEAL object from a string.
 * Compatible SEAL types: EncryptionParameters, Modulus, BigUInt, IntArray
 * @returns InvalidArgument if the decoding fails.
 **/
template <class T>
StatusOr<T> SEALDeserialize(const string& in) {
  T out;

  try {
    std::stringstream stream;
    stream << in;
    out.load(stream);
  } catch (const std::exception& e) {
    return InvalidArgumentError(e.what());
  }

  return out;
}

}  // namespace pir

#endif  // PIR_SERIALIZATION_H_
