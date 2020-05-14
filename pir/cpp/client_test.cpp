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
  auto payload = client_->CreateRequest(2, 10).ValueOrDie();
  auto out = client_->ProcessResponse(payload).ValueOrDie();

  for (size_t idx = 0; idx < 10; idx++) {
    ASSERT_TRUE(out[idx] == (idx == 2));
  }
}

}  // namespace
}  // namespace pir
