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
#include "payload.h"

#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "seal/seal.h"
#include "util/canonical_errors.h"
#include "util/status_macros.h"
#include "util/statusor.h"

namespace pir {

using ::private_join_and_compute::InvalidArgumentError;
using ::private_join_and_compute::StatusOr;

using seal::Ciphertext;

template <class T>
StatusOr<std::string> serialize(const T& sealobj) {
  std::stringstream stream;

  try {
    sealobj.save(stream);
  } catch (const std::exception& e) {
    return InvalidArgumentError(e.what());
  }

  return stream.str();
}

template <class T>
StatusOr<T> deserialize(const std::shared_ptr<seal::SEALContext>& sealctx,
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

StatusOr<PIRPayloadData> PIRPayloadData::Load(
    const std::vector<Ciphertext>& buff) {
  return PIRPayloadData(buff);
}

StatusOr<PIRPayloadData> PIRPayloadData::Load(
    const std::shared_ptr<seal::SEALContext>& sealctx,
    const std::string& encoded) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  std::stringstream stream;
  stream << encoded;
  PayloadData input;

  if (!input.ParseFromIstream(&stream)) {
    return InvalidArgumentError("failed to parse payload");
  }
  return PIRPayloadData::Load(sealctx, input);
}

StatusOr<PIRPayloadData> PIRPayloadData::Load(
    const std::shared_ptr<seal::SEALContext>& sealctx,
    const PayloadData& input) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;
  std::vector<Ciphertext> buff(input.data_size());
  for (int idx = 0; idx < input.data_size(); ++idx) {
    ASSIGN_OR_RETURN(buff[idx],
                     deserialize<Ciphertext>(sealctx, input.data(idx)));
  }
  return PIRPayloadData(buff);
}

StatusOr<std::string> PIRPayloadData::Save() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;
  std::stringstream stream;

  ASSIGN_OR_RETURN(auto output, SaveProto());

  if (!output.SerializeToOstream(&stream)) {
    return InvalidArgumentError("failed to save protobuffer");
  }

  return stream.str();
}

StatusOr<PayloadData> PIRPayloadData::SaveProto() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  PayloadData output;
  for (size_t idx = 0; idx < data_.size(); ++idx) {
    ASSIGN_OR_RETURN(auto ct, serialize<Ciphertext>(data_[idx]));
    output.add_data(ct);
  }

  return output;
}

StatusOr<PIRPayload> PIRPayload::Load(const PIRPayloadData& buff,
                                      const size_t& session_id) {
  return PIRPayload(buff, session_id);
}

StatusOr<PIRPayload> PIRPayload::Load(const PIRPayloadData& buff,
                                      const GaloisKeys& keys) {
  ASSIGN_OR_RETURN(auto keys_str, serialize<GaloisKeys>(keys));
  std::size_t session_id = std::hash<std::string>{}(keys_str);

  return PIRPayload(buff, session_id, keys);
}

StatusOr<PIRPayload> PIRPayload::Load(
    const std::shared_ptr<seal::SEALContext>& sealctx, const Payload& input) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;
  ASSIGN_OR_RETURN(auto buff, PIRPayloadData::Load(sealctx, input.data()));
  auto session = input.id();

  if (input.has_galoiskeys()) {
    ASSIGN_OR_RETURN(GaloisKeys keys,
                     deserialize<GaloisKeys>(sealctx, input.galoiskeys()));
    return PIRPayload(buff, session, keys);
  }
  return PIRPayload(buff, session);
}

StatusOr<PIRPayload> PIRPayload::Load(
    const std::shared_ptr<seal::SEALContext>& sealctx,
    const std::string& encoded) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  std::stringstream stream;
  stream << encoded;
  Payload input;

  if (!input.ParseFromIstream(&stream)) {
    return InvalidArgumentError("failed to parse session payload");
  }

  return Load(sealctx, input);
}

StatusOr<std::string> PIRPayload::Save() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  std::stringstream stream;

  ASSIGN_OR_RETURN(auto output, SaveProto());

  if (!output.SerializeToOstream(&stream)) {
    return InvalidArgumentError("failed to save protobuffer");
  }

  return stream.str();
}
StatusOr<Payload> PIRPayload::SaveProto() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  Payload output;

  ASSIGN_OR_RETURN(auto buff, PIRPayloadData::SaveProto());
  *output.mutable_data() = buff;
  output.set_id(session_id_);
  if (keys_) {
    ASSIGN_OR_RETURN(auto keys, serialize<GaloisKeys>(*keys_));
    output.set_galoiskeys(keys);
  }

  return output;
}

};  // namespace pir
