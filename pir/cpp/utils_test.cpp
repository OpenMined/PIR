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

#include "pir/cpp/utils.h"

#include "gtest/gtest.h"

namespace pir {
namespace {

TEST(NextPowerTwoTest, NextPowerTwo) {
  EXPECT_EQ(next_power_two(0), 1);
  EXPECT_EQ(next_power_two(1), 1);
  EXPECT_EQ(next_power_two(2), 2);
  EXPECT_EQ(next_power_two(3), 4);
  EXPECT_EQ(next_power_two(8), 8);
  EXPECT_EQ(next_power_two(9), 16);
  EXPECT_EQ(next_power_two(1 << 16), 65536);
  EXPECT_EQ(next_power_two((1 << 16) + 1), 131072);
  EXPECT_EQ(next_power_two((1UL << 30) + 1), 2147483648);
}

TEST(CeilLog2Test, CeilLog2) {
  EXPECT_EQ(ceil_log2(1), 0);
  EXPECT_EQ(ceil_log2(2), 1);
  EXPECT_EQ(ceil_log2(3), 2);
  EXPECT_EQ(ceil_log2(8), 3);
  EXPECT_EQ(ceil_log2(15), 4);
  EXPECT_EQ(ceil_log2(16), 4);
  EXPECT_EQ(ceil_log2(17), 5);
  EXPECT_EQ(ceil_log2((1 << 16) - 1), 16);
  EXPECT_EQ(ceil_log2(1 << 16), 16);
  EXPECT_EQ(ceil_log2((1 << 16) + 1), 17);
  EXPECT_EQ(ceil_log2(1UL << 31), 31);
}

TEST(Log2Test, Log2) {
  EXPECT_EQ(log2(1), 0);
  EXPECT_EQ(log2(2), 1);
  EXPECT_EQ(log2(3), 1);
  EXPECT_EQ(log2(8), 3);
  EXPECT_EQ(log2(15), 3);
  EXPECT_EQ(log2(16), 4);
  EXPECT_EQ(log2(17), 4);
  EXPECT_EQ(log2((1 << 16) - 1), 15);
  EXPECT_EQ(log2(1 << 16), 16);
  EXPECT_EQ(log2((1 << 16) + 1), 16);
  EXPECT_EQ(log2((1UL << 31) - 1), 30);
  EXPECT_EQ(log2(1UL << 31), 31);
}

}  // namespace
}  // namespace pir
