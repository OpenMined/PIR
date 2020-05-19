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

#include <vector>

#include "context.h"
#include "database.h"
#include "payload.h"
#include "seal/seal.h"
#include "util/statusor.h"

namespace pir {

using ::private_join_and_compute::StatusOr;

class PIRServer {
 public:
  /**
   * Creates and returns a new server instance, holding a database.
   * @param[in] db RawDatabase to load
   * @param[in] params PIR Paramerters
   * @returns InvalidArgument if the database encoding fails
   **/
  static StatusOr<std::unique_ptr<PIRServer>> Create(
      const std::unique_ptr<RawDatabase>& database,
      std::shared_ptr<PIRParameters> params);
  /**
   * Creates and returns a new server instance, holding a database.
   * @param[in] db RawDatabase to load
   * @returns InvalidArgument if the database encoding fails
   **/
  static StatusOr<std::unique_ptr<PIRServer>> Create(
      const std::unique_ptr<RawDatabase>& database);

  /**
   * Handles a client request.
   * @param[in] request The PIR Payload
   * @returns InvalidArgument if the deserialization or encrypted operations
   *fail
   **/
  StatusOr<PIRPayload> ProcessRequest(const PIRPayload& request) const;

  /**
   * Returns the database size.
   **/
  std::size_t DBSize() { return context_->DBSize(); }

  PIRServer() = delete;

 private:
  PIRServer(std::unique_ptr<PIRContext> /*sealctx*/,
            std::unique_ptr<PIRDatabase> /*db*/);

  std::unique_ptr<PIRContext> context_;
  std::unique_ptr<PIRDatabase> db_;
};

}  // namespace pir

#endif  // PIR_SERVER_H_
