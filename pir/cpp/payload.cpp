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

#include "payload.pb.h"
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

PIRPayload PIRPayload::Load(const std::vector<Ciphertext>& buff,
                            const optional<GaloisKeys>& keys) {
  return PIRPayload(buff, keys);
}

StatusOr<PIRPayload> PIRPayload::Load(
    const std::shared_ptr<seal::SEALContext>& sealctx,
    const std::string& encoded) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  std::stringstream stream;
  stream << encoded;
  Payload input;

  if (!input.ParseFromIstream(&stream)) {
    return InvalidArgumentError("failed to parse payload");
  }

  std::vector<Ciphertext> buff(input.query_size());
  for (int idx = 0; idx < input.query_size(); ++idx) {
    ASSIGN_OR_RETURN(buff[idx],
                     deserialize<Ciphertext>(sealctx, input.query(idx)));
  }
  optional<GaloisKeys> keys;
  auto rawkeys = deserialize<GaloisKeys>(sealctx, input.galoiskeys());
  if (rawkeys.ok()) {
    keys = rawkeys.ValueOrDie();
  }

  return PIRPayload(buff, keys);
}

StatusOr<std::string> PIRPayload::Save() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  Payload output;
  for (size_t idx = 0; idx < buff_.size(); ++idx) {
    ASSIGN_OR_RETURN(auto ct, serialize<Ciphertext>(buff_[idx]));
    output.add_query(ct);
  }

  if (keys_) {
    ASSIGN_OR_RETURN(auto keys, serialize<GaloisKeys>(*keys_));
    output.set_galoiskeys(keys);
  }

  std::stringstream stream;

  if (!output.SerializeToOstream(&stream)) {
    return InvalidArgumentError("failed to save protobuffer");
  }

  return stream.str();
}
};  // namespace pir
