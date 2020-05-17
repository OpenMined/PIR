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

#include <algorithm>
#include <iostream>
#include <vector>

#include "client.h"
#include "gtest/gtest.h"

namespace pir {
namespace {

class PIRServerTest : public ::testing::Test {
 protected:
};

TEST_F(PIRServerTest, TestCorrectness) {
  constexpr std::size_t dbsize = 1000;
  std::vector<std::uint64_t> db(dbsize, 0);

  std::generate(db.begin(), db.end(), [n = 0]() mutable {
    ++n;
    return 4 * n;
  });

  auto server_ = PIRServer::Create(db).ValueOrDie();
  ASSERT_TRUE(server_ != nullptr);

  auto params = server_->Params().ValueOrDie();

  for (auto& client_ :
       {PIRClient::Create(server_->DBSize()),
        PIRClient::CreateFromParams(params, dbsize).ValueOrDie()}) {
    size_t desiredIndex = 23;
    auto payload = client_->CreateRequest(desiredIndex).ValueOrDie();
    auto response = server_->ProcessRequest(payload).ValueOrDie();
    auto out = client_->ProcessResponse(response).ValueOrDie();

    for (size_t idx = 0; idx < dbsize; idx++) {
      if (idx != desiredIndex) {
        ASSERT_TRUE(out[idx] == 0);
        continue;
      }
      ASSERT_TRUE(out[idx] == db[idx]);
    }
  }
}
}  // namespace
}  // namespace pir
