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

#ifndef PIR_SERVER_H_
#define PIR_SERVER_H_

#include <string>
#include <vector>

#include "context.h"
#include "util/statusor.h"

namespace pir {

using ::private_join_and_compute::StatusOr;

class PIRServer {
 public:
  // Creates and returns a new server instance.
  static StatusOr<std::unique_ptr<PIRServer>> Create();

  StatusOr<std::string> ProcessRequest(const std::string& request) const;

  StatusOr<int> PopulateDatabase(const std::vector<std::string>& db);

  PIRServer() = delete;

 private:
  PIRServer(std::unique_ptr<PIRContext>);

  std::unique_ptr<PIRContext> context_;
};

}  // namespace pir

#endif  // PIR_SERVER_H_
