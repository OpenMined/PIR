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

StatusOr<std::string> serializeCT(const Ciphertext& ciphertext) {
  std::stringstream stream;

  try {
    ciphertext.save(stream);
  } catch (const std::exception& e) {
    return InvalidArgumentError(e.what());
  }

  return stream.str();
}

StatusOr<Ciphertext> deserializeCT(
    const std::shared_ptr<seal::SEALContext>& sealctx, const std::string& in) {
  Ciphertext ciphertext(sealctx);

  try {
    std::stringstream stream;
    stream << in;
    ciphertext.load(sealctx, stream);
  } catch (const std::exception& e) {
    return InvalidArgumentError(e.what());
  }

  return ciphertext;
}

PIRPayload PIRPayload::Load(const std::vector<Ciphertext>& buff,
                            const optional<GaloisKeys>& keys) {
  return PIRPayload(buff, keys);
}

StatusOr<PIRPayload> PIRPayload::Load(
    const std::shared_ptr<seal::SEALContext>& sealctx,
    const std::string& encoded) {
  rapidjson::Document request;
  request.Parse(encoded.data(), encoded.size());
  if (request.HasParseError()) {
    return InvalidArgumentError("failed to parse encoded string");
  }

  if (!request.IsArray()) {
    return InvalidArgumentError("payload should be array");
  }

  size_t size = request.GetArray().Size();

  std::vector<Ciphertext> buff(size);
  for (size_t idx = 0; idx < size; ++idx) {
    if (!request[idx].IsString())
      return InvalidArgumentError("elements must be string");

    std::string encoded(request[idx].GetString(),
                        request[idx].GetStringLength());

    ASSIGN_OR_RETURN(buff[idx], deserializeCT(sealctx, encoded));
  }

  return PIRPayload(buff);
}

StatusOr<std::string> PIRPayload::Save() {
  std::vector<std::string> interm(buff_.size());

  for (size_t idx = 0; idx < buff_.size(); ++idx) {
    ASSIGN_OR_RETURN(interm[idx], serializeCT(buff_[idx]));
  }

  rapidjson::Document output;
  output.SetArray();
  for (size_t idx = 0; idx < buff_.size(); ++idx) {
    output.PushBack(
        rapidjson::Value().SetString(interm[idx].data(), interm[idx].size(),
                                     output.GetAllocator()),
        output.GetAllocator());
  }

  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  output.Accept(writer);

  return std::string(buffer.GetString());
}

const buff_type& PIRPayload::Get() const { return buff_; }
};  // namespace pir
