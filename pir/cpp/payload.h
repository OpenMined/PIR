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

class PIRCiphertexts {
 public:
  /**
   * Loads the PIR ciphertexts.
   **/
  static StatusOr<PIRCiphertexts> Load(const buff_type& ct);
  /**
   * Decodes and loads a PIR Ciphertext.
   * @returns InvalidArgument if the decoding fails
   **/
  static StatusOr<PIRCiphertexts> Load(
      const std::shared_ptr<seal::SEALContext>& ctx,
      const std::string& encoded);

  static StatusOr<PIRCiphertexts> Load(
      const std::shared_ptr<seal::SEALContext>& ctx,
      const Ciphertexts& encoded);
  /**
   * Saves the PIR Ciphertexts to an encoding.
   * @returns InvalidArgument if the encoding fails
   **/
  StatusOr<std::string> Save();
  StatusOr<Ciphertexts> SaveProto();
  /**
   * Returns a reference to the internal buffer.
   **/
  const buff_type& Get() const { return ct_; }
  PIRCiphertexts() = delete;

  PIRCiphertexts(const buff_type& ct) : ct_(ct){};

 private:
  buff_type ct_;
};

class PIRQuery : public PIRCiphertexts {
 public:
  /**
   * Loads a PIR Request.
   **/
  static StatusOr<PIRQuery> Load(const PIRCiphertexts& data,
                                 const GaloisKeys& keys);
  /**
   * Decodes and loads a PIR Query.
   * @returns InvalidArgument if the decoding fails
   **/
  static StatusOr<PIRQuery> Load(const std::shared_ptr<seal::SEALContext>& ctx,
                                 const std::string& encoded);
  static StatusOr<PIRQuery> Load(const std::shared_ptr<seal::SEALContext>& ctx,
                                 const Query& encoded);
  /**
   * Saves the PIR Query to a string.
   * @returns InvalidArgument if the encoding fails
   **/
  StatusOr<std::string> Save();
  StatusOr<Query> SaveProto();

  const GaloisKeys& GetKeys() const { return keys_; }

  PIRQuery() = delete;

 private:
  PIRQuery(const PIRCiphertexts& data, const GaloisKeys& keys)
      : PIRCiphertexts(data), keys_(keys){};

  GaloisKeys keys_;
};

class PIRReply : public PIRCiphertexts {
 public:
  /**
   * Loads a PIR Reply.
   **/
  static StatusOr<PIRReply> Load(const PIRCiphertexts& data);
  /**
   * Decodes and loads a PIR Reply.
   * @returns InvalidArgument if the decoding fails
   **/
  static StatusOr<PIRReply> Load(const std::shared_ptr<seal::SEALContext>& ctx,
                                 const std::string& encoded);
  static StatusOr<PIRReply> Load(const std::shared_ptr<seal::SEALContext>& ctx,
                                 const Reply& encoded);
  /**
   * Saves the PIR Reply to a string.
   * @returns InvalidArgument if the encoding fails
   **/
  StatusOr<std::string> Save();
  StatusOr<Reply> SaveProto();

  PIRReply() = delete;

 private:
  PIRReply(const PIRCiphertexts& data) : PIRCiphertexts(data){};
};

}  // namespace pir

#endif  // PIR_PAYLOAD_H_
