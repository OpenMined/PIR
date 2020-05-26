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

PIRPayload PIRPayload::Load(const std::vector<Ciphertext>& buff,
                            const optional<GaloisKeys>& keys) {
  return PIRPayload(buff, keys);
}

StatusOr<PIRPayload> PIRPayload::Load(
    const std::shared_ptr<seal::SEALContext>& sealctx,
    const std::string& encoded) {
  rapidjson::Document payload;
  payload.Parse(encoded.data(), encoded.size());
  if (payload.HasParseError()) {
    return InvalidArgumentError("failed to parse payload");
  }
  if (!payload.IsObject()) {
    return InvalidArgumentError("payload should be object");
  }
  const char* buffkey = "buffer";
  if (!payload.HasMember(buffkey)) {
    return InvalidArgumentError("failed to parse buffer");
  }

  auto& request = payload[buffkey];

  if (!request.IsArray()) {
    return InvalidArgumentError("buffer should be array");
  }

  size_t size = request.GetArray().Size();

  std::vector<Ciphertext> buff(size);
  for (size_t idx = 0; idx < size; ++idx) {
    if (!request[idx].IsString())
      return InvalidArgumentError("elements must be string");

    std::string encoded(request[idx].GetString(),
                        request[idx].GetStringLength());

    ASSIGN_OR_RETURN(buff[idx], deserialize<Ciphertext>(sealctx, encoded));
  }

  optional<GaloisKeys> keys;
  if (payload.HasMember("galois_keys")) {
    // ASSIGN_OR_RETURN(keys, deserialize<GaloisKeys>(sealctx,
    // payload["galois_keys"].GetString()));
  }

  return PIRPayload(buff, keys);
}

StatusOr<std::string> PIRPayload::Save() {
  std::vector<std::string> interm(buff_.size());

  rapidjson::Document output;
  output.SetObject();

  // internal buffer
  for (size_t idx = 0; idx < buff_.size(); ++idx) {
    ASSIGN_OR_RETURN(interm[idx], serialize<Ciphertext>(buff_[idx]));
  }

  rapidjson::Document payloadbuff(&output.GetAllocator());
  payloadbuff.SetArray();
  for (size_t idx = 0; idx < buff_.size(); ++idx) {
    payloadbuff.PushBack(
        rapidjson::Value().SetString(interm[idx].data(), interm[idx].size(),
                                     payloadbuff.GetAllocator()),
        payloadbuff.GetAllocator());
  }
  output.AddMember("buffer", payloadbuff, output.GetAllocator());

  if (keys_) {
    ASSIGN_OR_RETURN(auto keys, serialize<GaloisKeys>(*keys_));
    output.AddMember("galois_keys",
                     rapidjson::Value().SetString(keys.data(), keys.size(),
                                                  output.GetAllocator()),
                     output.GetAllocator());
  }

  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  output.Accept(writer);

  return std::string(buffer.GetString());
}
};  // namespace pir
