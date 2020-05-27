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

StatusOr<PIRCiphertexts> PIRCiphertexts::Load(
    const std::vector<Ciphertext>& buff) {
  return PIRCiphertexts(buff);
}

StatusOr<PIRCiphertexts> PIRCiphertexts::Load(
    const std::shared_ptr<seal::SEALContext>& sealctx,
    const std::string& encoded) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  std::stringstream stream;
  stream << encoded;
  Ciphertexts input;

  if (!input.ParseFromIstream(&stream)) {
    return InvalidArgumentError("failed to parse payload");
  }
  return PIRCiphertexts::Load(sealctx, input);
}

StatusOr<PIRCiphertexts> PIRCiphertexts::Load(
    const std::shared_ptr<seal::SEALContext>& sealctx,
    const Ciphertexts& input) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;
  std::vector<Ciphertext> buff(input.ct_size());
  for (int idx = 0; idx < input.ct_size(); ++idx) {
    ASSIGN_OR_RETURN(buff[idx],
                     deserialize<Ciphertext>(sealctx, input.ct(idx)));
  }
  return PIRCiphertexts(buff);
}

StatusOr<std::string> PIRCiphertexts::Save() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;
  std::stringstream stream;

  ASSIGN_OR_RETURN(auto output, SaveProto());

  if (!output.SerializeToOstream(&stream)) {
    return InvalidArgumentError("failed to save protobuffer");
  }

  return stream.str();
}

StatusOr<Ciphertexts> PIRCiphertexts::SaveProto() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  Ciphertexts output;
  for (size_t idx = 0; idx < ct_.size(); ++idx) {
    ASSIGN_OR_RETURN(auto ct, serialize<Ciphertext>(ct_[idx]));
    output.add_ct(ct);
  }

  return output;
}

StatusOr<PIRQuery> PIRQuery::Load(const PIRCiphertexts& buff,
                                  const GaloisKeys& keys) {
  ASSIGN_OR_RETURN(auto keys_str, serialize<GaloisKeys>(keys));

  return PIRQuery(buff, keys);
}

StatusOr<PIRQuery> PIRQuery::Load(
    const std::shared_ptr<seal::SEALContext>& sealctx, const Query& input) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;
  ASSIGN_OR_RETURN(auto buff, PIRCiphertexts::Load(sealctx, input.query()));

  ASSIGN_OR_RETURN(GaloisKeys keys,
                   deserialize<GaloisKeys>(sealctx, input.keys()));
  return PIRQuery(buff, keys);
}

StatusOr<PIRQuery> PIRQuery::Load(
    const std::shared_ptr<seal::SEALContext>& sealctx,
    const std::string& encoded) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  std::stringstream stream;
  stream << encoded;
  Query input;

  if (!input.ParseFromIstream(&stream)) {
    return InvalidArgumentError("failed to parse payload");
  }

  return Load(sealctx, input);
}

StatusOr<std::string> PIRQuery::Save() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  std::stringstream stream;

  ASSIGN_OR_RETURN(auto output, SaveProto());

  if (!output.SerializeToOstream(&stream)) {
    return InvalidArgumentError("failed to save query");
  }

  return stream.str();
}
StatusOr<Query> PIRQuery::SaveProto() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  Query output;

  ASSIGN_OR_RETURN(auto buff, PIRCiphertexts::SaveProto());
  *output.mutable_query() = buff;
  ASSIGN_OR_RETURN(auto keys, serialize<GaloisKeys>(keys_));
  output.set_keys(keys);

  return output;
}

StatusOr<PIRReply> PIRReply::Load(const PIRCiphertexts& buff) {
  return PIRReply(buff);
}

StatusOr<PIRReply> PIRReply::Load(
    const std::shared_ptr<seal::SEALContext>& sealctx, const Reply& input) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;
  ASSIGN_OR_RETURN(auto buff, PIRCiphertexts::Load(sealctx, input.reply()));
  return PIRReply(buff);
}

StatusOr<PIRReply> PIRReply::Load(
    const std::shared_ptr<seal::SEALContext>& sealctx,
    const std::string& encoded) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  std::stringstream stream;
  stream << encoded;
  Reply input;

  if (!input.ParseFromIstream(&stream)) {
    return InvalidArgumentError("failed to parse reply");
  }

  return Load(sealctx, input);
}

StatusOr<std::string> PIRReply::Save() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  std::stringstream stream;

  ASSIGN_OR_RETURN(auto output, SaveProto());

  if (!output.SerializeToOstream(&stream)) {
    return InvalidArgumentError("failed to save protobuffer");
  }

  return stream.str();
}

StatusOr<Reply> PIRReply::SaveProto() {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  Reply output;

  ASSIGN_OR_RETURN(auto buff, PIRCiphertexts::SaveProto());
  *output.mutable_reply() = buff;

  return output;
}

};  // namespace pir
