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

#include "client.h"

#include "gtest/gtest.h"

namespace pir {
namespace {

class PIRClientTest : public ::testing::Test {
 protected:
  void SetUp() {
    client_ = PIRClient::Create().ValueOrDie();
    ASSERT_TRUE(client_ != nullptr);
  }

  std::unique_ptr<PIRClient> client_;
};

TEST_F(PIRClientTest, TestSanity) {
  constexpr std::size_t dbSize = 1000;
  size_t desiredIndex = 23;

  auto payload = client_->CreateRequest(desiredIndex, dbSize).ValueOrDie();
  auto out = client_->ProcessResponse(payload).ValueOrDie();

  for (size_t idx = 0; idx < dbSize; idx++) {
    ASSERT_TRUE(out[idx] == (idx == desiredIndex));
  }
}

}  // namespace
}  // namespace pir
