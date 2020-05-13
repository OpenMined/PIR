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
#include "server.h"

#include "seal/seal.h"

namespace pir {

PIRServer::PIRServer(const seal::EncryptionParameters& params) {}

std::unique_ptr<PIRServer> PIRServer::Create(
    const seal::EncryptionParameters& params) {
  return std::unique_ptr<PIRServer>(new PIRServer(params));
}

std::optional<std::string> PIRServer::ProcessRequest(
    const std::string& request) const {
  return {};
}

int PIRServer::PopulateDatabase(const std::vector<std::string>& database) {
  return {};
}

}  // namespace pir
