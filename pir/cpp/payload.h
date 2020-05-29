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

#include <optional>
#include <string>

#include "pir/proto/payload.pb.h"
#include "seal/seal.h"
#include "util/statusor.h"

namespace pir {

using ::private_join_and_compute::StatusOr;
using seal::GaloisKeys;
using std::optional;
using buff_type = std::vector<seal::Ciphertext>;

class DecodedCiphertexts {
 public:
  /**
   * Loads the PIR ciphertexts.
   * @param[in] The ciphertexts buffers
   **/
  static DecodedCiphertexts Load(const buff_type& ct);
  /**
   * Decodes and loads a PIR Ciphertext.
   * @param[in] The SEAL context, for buffer allocations.
   * @param[in] The encoded ciphertext.
   * @returns InvalidArgument if the decoding fails.
   **/
  static StatusOr<DecodedCiphertexts> Load(
      const std::shared_ptr<seal::SEALContext>& ctx,
      const Ciphertexts& encoded);
  /**
   * Saves the Ciphertexts to a protobuffer.
   * @returns InvalidArgument if the encoding fails
   **/
  StatusOr<Ciphertexts> Save();
  /**
   * Returns a reference to the plain internal buffer.
   **/
  const buff_type& Get() const { return ct_; }
  DecodedCiphertexts() = delete;

  DecodedCiphertexts(const buff_type& ct) : ct_(ct){};

 private:
  buff_type ct_;
};

class DecodedQuery : public DecodedCiphertexts {
 public:
  /**
   * Loads a PIR Request.
   **/
  static DecodedQuery Load(const DecodedCiphertexts& buff,
                           const GaloisKeys& keys);
  /**
   * Decodes and loads a PIR Query.
   * @returns InvalidArgument if the decoding fails
   **/
  static StatusOr<DecodedQuery> Load(
      const std::shared_ptr<seal::SEALContext>& ctx, const Query& encoded);
  /**
   * Saves the PIR Query to a string.
   * @returns InvalidArgument if the encoding fails
   **/
  StatusOr<Query> Save();

  const GaloisKeys& GetKeys() const { return keys_; }
  DecodedQuery() = delete;

 private:
  DecodedQuery(const DecodedCiphertexts& buff, const GaloisKeys& keys)
      : DecodedCiphertexts(buff), keys_(keys){};

  GaloisKeys keys_;
};

class DecodedReply : public DecodedCiphertexts {
 public:
  /**
   * Loads a PIR Reply.
   **/
  static DecodedReply Load(const DecodedCiphertexts& buff);
  /**
   * Decodes and loads a PIR Reply.
   * @returns InvalidArgument if the decoding fails
   **/
  static StatusOr<DecodedReply> Load(
      const std::shared_ptr<seal::SEALContext>& ctx, const Reply& encoded);
  /**
   * Saves the PIR Reply to a string.
   * @returns InvalidArgument if the encoding fails
   **/
  StatusOr<Reply> Save();

  DecodedReply() = delete;

 private:
  DecodedReply(const DecodedCiphertexts& buff) : DecodedCiphertexts(buff){};
};

}  // namespace pir

#endif  // PIR_PAYLOAD_H_
