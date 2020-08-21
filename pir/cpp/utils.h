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

#ifndef PIR_UTILS_H_
#define PIR_UTILS_H_

#include <cstdint>
#include <vector>

namespace pir {

// Utility function to generate Galois elements needed for Oblivious Expansion.
std::vector<uint32_t> generate_galois_elts(uint64_t N);

// Utility function to find the next highest power of 2 of a given number.
template <typename t>
t next_power_two(t n) {
  if (n == 0) return 1;
  --n;
  for (size_t i = 1; i < sizeof(n) * 8; i = i << 1) {
    n |= n >> i;
  }
  return n + 1;
}

// Utility function to find the log base 2 of v rounded up.
uint32_t ceil_log2(uint32_t v);

// Utility function to find the log base 2 of v truncated.
uint32_t log2(uint32_t v);

// Utility function to calculate integer power
inline size_t ipow(size_t base, size_t exp) {
  size_t result = 1;
  for (;;) {
    if (exp & 1) {
      result *= base;
    }
    exp >>= 1;
    if (!exp) break;
    base *= base;
  }
  return result;
}

}  // namespace pir

namespace private_join_and_compute {
// Really don't know why this isn't included with private_join_and_compute

// Run a command that returns a util::Status.  If the called code returns an
// error status, return that status up out of this method too.
//
// Example:
//   RETURN_IF_ERROR(DoThings(4));
#define RETURN_IF_ERROR(expr)                                                \
  do {                                                                       \
    /* Using _status below to avoid capture problems if expr is "status". */ \
    const Status _status = (expr);                                           \
    if (!_status.ok()) return _status;                                       \
  } while (0)

}  // namespace private_join_and_compute

#endif  // PIR_UTILS_H_
