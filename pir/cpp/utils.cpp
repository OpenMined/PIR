#include "pir/cpp/utils.h"

namespace pir {

using std::vector;

vector<uint32_t> generate_galois_elts(uint64_t N) {
  const size_t logN = ceil_log2(N);
  vector<uint32_t> galois_elts(logN);
  for (size_t i = 0; i < logN; ++i) {
    galois_elts[i] = (N >> i) + 1;
  }
  return galois_elts;
}

uint32_t log2(uint32_t v) {
  static const int MultiplyDeBruijnBitPosition[32] = {
      0, 9,  1,  10, 13, 21, 2,  29, 11, 14, 16, 18, 22, 25, 3, 30,
      8, 12, 20, 28, 15, 17, 24, 7,  19, 27, 23, 6,  26, 5,  4, 31};

  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;

  return MultiplyDeBruijnBitPosition[(uint32_t)(v * 0x07C4ACDDU) >> 27];
}

uint32_t ceil_log2(uint32_t v) {
  static const int MultiplyDeBruijnBitPosition[32] = {
      0,  1,  28, 2,  29, 14, 24, 3, 30, 22, 20, 15, 25, 17, 4,  8,
      31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18, 6,  11, 5,  10, 9};

  --v;
  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;
  ++v;

  return MultiplyDeBruijnBitPosition[(uint32_t)(v * 0x077CB531U) >> 27];
}

}  // namespace pir
