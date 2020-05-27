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

class PIRPayloadData {
 public:
  /**
   * Loads a PIR Payload.
   **/
  static StatusOr<PIRPayloadData> Load(const buff_type& data);
  /**
   * Decodes and loads a PIR Payload.
   * @returns InvalidArgument if the decoding fails
   **/
  static StatusOr<PIRPayloadData> Load(
      const std::shared_ptr<seal::SEALContext>& ctx,
      const std::string& encoded);

  static StatusOr<PIRPayloadData> Load(
      const std::shared_ptr<seal::SEALContext>& ctx, const PayloadData& encoded);
  /**
   * Saves the PIR Payload to a string.
   * @returns InvalidArgument if the encoding fails
   **/
  StatusOr<std::string> Save();
  StatusOr<PayloadData> SaveProto();
  /**
   * Returns a reference to the internal buffer.
   **/
  const buff_type& Get() const { return data_; }
  PIRPayloadData() = delete;

  PIRPayloadData(const buff_type& data) : data_(data){};

 private:
  buff_type data_;
};

class PIRSessionPayload : public PIRPayloadData {
 public:
  /**
   * Loads a PIR Session Payload.
   **/
  static StatusOr<PIRSessionPayload> Load(const PIRPayloadData& data,
                                          const size_t& session);
  static StatusOr<PIRSessionPayload> Load(const PIRPayloadData& data,
                                          const GaloisKeys& keys);
  /**
   * Decodes and loads a PIR Session Payload.
   * @returns InvalidArgument if the decoding fails
   **/
  static StatusOr<PIRSessionPayload> Load(
      const std::shared_ptr<seal::SEALContext>& ctx,
      const std::string& encoded);
  static StatusOr<PIRSessionPayload> Load(
      const std::shared_ptr<seal::SEALContext>& ctx,
      const Payload& encoded);
  /**
   * Saves the PIR Session Payload to a string.
   * @returns InvalidArgument if the encoding fails
   **/
  StatusOr<std::string> Save();
  StatusOr<Payload> SaveProto();
  /**
   * Returns a reference to the session ID.
   **/
  std::size_t GetID() const { return session_id_; }
  const optional<GaloisKeys>& GetKeys() const { return keys_; }

  PIRSessionPayload() = delete;

 private:
  PIRSessionPayload(const PIRPayloadData& data, const std::size_t& session_id)
      : PIRPayloadData(data), session_id_(session_id){};

  PIRSessionPayload(const PIRPayloadData& data, const std::size_t& session_id,
                    const GaloisKeys& keys)
      : PIRPayloadData(data), session_id_(session_id), keys_(keys){};

  std::size_t session_id_;
  optional<GaloisKeys> keys_;
};

}  // namespace pir

#endif  // PIR_PAYLOAD_H_
