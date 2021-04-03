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

#include "absl/memory/memory.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/types/span.h"

#define ASSERT_OK(expr)                                           \
  do {                                                            \
    const Status _status = (expr);                                \
    ASSERT_TRUE(_status.ok()) << "Error: " << _status.ToString(); \
  } while (false)

#define EXPECT_OK(expr)                                           \
  do {                                                            \
    const Status _status = (expr);                                \
    EXPECT_TRUE(_status.ok()) << "Error: " << _status.ToString(); \
  } while (false)

#define ASSIGN_OR_FAIL(lhs, rexpr) \
  ASSIGN_OR_FAIL_IMPL_(CONCAT_NAME_(status_or_, __LINE__), lhs, rexpr)

#define ASSIGN_OR_RETURN(lhs, rexpr) \
  ASSIGN_OR_RETURN_IMPL_(CONCAT_NAME_(status_or_, __LINE__), lhs, rexpr)

#define CONCAT_NAME_INNER_(x, y) x##y
#define CONCAT_NAME_(x, y) CONCAT_NAME_INNER_(x, y)

#define ASSIGN_OR_FAIL_IMPL_(statusor, lhs, rexpr)                         \
  auto statusor = (rexpr);                                                 \
  ASSERT_TRUE(statusor.ok()) << "Error: " << statusor.status().ToString(); \
  lhs = std::move(*statusor);

#define ASSIGN_OR_RETURN_IMPL_(statusor, lhs, rexpr) \
  auto statusor = (rexpr);                           \
  if (!statusor.ok()) return statusor.status();      \
  lhs = std::move(*statusor);
