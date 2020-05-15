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

#ifndef PIR_CLIENT_H_
#define PIR_CLIENT_H_

#include <string>

#include "context.h"
#include "util/statusor.h"

namespace pir {

using ::private_join_and_compute::StatusOr;

class PIRClient {
 public:
  /**
   * Creates and returns a new client instance.
   * @returns TODO
   **/
  static StatusOr<std::unique_ptr<PIRClient>> Create();

  /**
   * Creates and returns a new client instance, from existing parameters
   * @param[in] params Serialized PIR parameters
   * @returns TODO
   **/
  static StatusOr<std::unique_ptr<PIRClient>> CreateFromParams(
      const std::string& params);

  /**
   * Creates a new payload request
   * @param[in] desiredIndex Expected database value from an index
   * @param[in] dbSize Database size
   * @returns TODO
   **/
  StatusOr<std::string> CreateRequest(std::size_t desiredIndex,
                                      std::size_t dbSize) const;

  /**
   * Extracts server response
   * @param[in] response Server output
   * @returns TODO
   **/
  StatusOr<std::vector<std::uint64_t>> ProcessResponse(
      const std::string& response) const;

  PIRClient() = delete;

 private:
  PIRClient(std::unique_ptr<PIRContext>);

  std::unique_ptr<PIRContext> context_;
};

}  // namespace pir

#endif  // PIR_CLIENT_H_
