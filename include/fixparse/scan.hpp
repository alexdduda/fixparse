// SOH (0x01) structural indexing.
//
// A FIX message is a sequence of `tag=value<SOH>` fields. Finding every SOH is
// the only part of parsing that touches every byte, so it is the part worth
// vectorizing. Each scanner writes the byte offsets of every SOH in [p, p+n)
// into `out` and returns how many it found, or kOverflow if there were more
// than `cap`. All variants must produce identical output; the tests and the
// fuzz driver check that differentially.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#if defined(__ARM_NEON)
#include <arm_neon.h>
#endif
#if defined(__SSE2__)
#include <emmintrin.h>
#endif

namespace fixparse {

inline constexpr char kSOH = '\x01';
inline constexpr std::size_t kOverflow = static_cast<std::size_t>(-1);

enum class Scan { Scalar, Swar, Neon, Sse2, Best };

namespace detail {

// Appends p-relative offsets for every set "marker" bit. `bits_per_byte` is 1
// for movemask-style masks and 4 for NEON nibble masks.
template <unsigned Shift>
inline bool emit_bits(std::uint64_t m, std::uint32_t base, std::uint32_t* out,
                      std::size_t& k, std::size_t cap) {
  while (m) {
    if (k == cap) return false;
    out[k++] = base + static_cast<std::uint32_t>(__builtin_ctzll(m) >> Shift);
    m &= m - 1;
  }
  return true;
}

inline std::size_t scan_tail(const char* p, std::size_t i, std::size_t n,
                             std::uint32_t* out, std::size_t k, std::size_t cap) {
  for (; i < n; ++i) {
    if (p[i] == kSOH) {
      if (k == cap) return kOverflow;
      out[k++] = static_cast<std::uint32_t>(i);
    }
  }
  return k;
}

}  // namespace detail

inline std::size_t scan_scalar(const char* p, std::size_t n, std::uint32_t* out,
                               std::size_t cap) {
  return detail::scan_tail(p, 0, n, out, 0, cap);
}

// SWAR: eight bytes per step in a plain 64-bit register. Portable to any
// little-endian target. Uses the exact zero-byte test (no false positives from
// borrow propagation, unlike the shorter `(x - 0x01..) & ~x & 0x80..` form).
inline std::size_t scan_swar(const char* p, std::size_t n, std::uint32_t* out,
                             std::size_t cap) {
  constexpr std::uint64_t kOnes = 0x0101010101010101ULL;
  constexpr std::uint64_t kLow7 = 0x7F7F7F7F7F7F7F7FULL;
  std::size_t i = 0, k = 0;
  for (; i + 8 <= n; i += 8) {
    std::uint64_t w;
    std::memcpy(&w, p + i, 8);
    const std::uint64_t x = w ^ kOnes;  // SOH bytes become 0x00
    const std::uint64_t z = ~(((x & kLow7) + kLow7) | x | kLow7);
    if (z && !detail::emit_bits<3>(z, static_cast<std::uint32_t>(i), out, k, cap))
      return kOverflow;
  }
  return detail::scan_tail(p, i, n, out, k, cap);
}

#if defined(__ARM_NEON)
// NEON has no movemask instruction. The standard workaround narrows each
// 16-bit lane by 4 bits, which packs a 16-byte comparison into a 64-bit
// nibble mask: byte i of the vector becomes nibble i of the result.
inline std::size_t scan_neon(const char* p, std::size_t n, std::uint32_t* out,
                             std::size_t cap) {
  const uint8x16_t soh = vdupq_n_u8(0x01);
  std::size_t i = 0, k = 0;
  for (; i + 16 <= n; i += 16) {
    const uint8x16_t v = vld1q_u8(reinterpret_cast<const std::uint8_t*>(p + i));
    const uint8x16_t eq = vceqq_u8(v, soh);
    const uint8x8_t nib = vshrn_n_u16(vreinterpretq_u16_u8(eq), 4);
    std::uint64_t m = vget_lane_u64(vreinterpret_u64_u8(nib), 0);
    m &= 0x8888888888888888ULL;  // keep one bit per matching byte
    if (m && !detail::emit_bits<2>(m, static_cast<std::uint32_t>(i), out, k, cap))
      return kOverflow;
  }
  return detail::scan_tail(p, i, n, out, k, cap);
}
#endif

#if defined(__SSE2__)
inline std::size_t scan_sse2(const char* p, std::size_t n, std::uint32_t* out,
                             std::size_t cap) {
  const __m128i soh = _mm_set1_epi8(0x01);
  std::size_t i = 0, k = 0;
  for (; i + 16 <= n; i += 16) {
    const __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i*>(p + i));
    const auto m = static_cast<std::uint64_t>(
        static_cast<unsigned>(_mm_movemask_epi8(_mm_cmpeq_epi8(v, soh))));
    if (m && !detail::emit_bits<0>(m, static_cast<std::uint32_t>(i), out, k, cap))
      return kOverflow;
  }
  return detail::scan_tail(p, i, n, out, k, cap);
}
#endif

inline constexpr bool scan_available(Scan s) {
  switch (s) {
    case Scan::Neon:
#if defined(__ARM_NEON)
      return true;
#else
      return false;
#endif
    case Scan::Sse2:
#if defined(__SSE2__)
      return true;
#else
      return false;
#endif
    default:
      return true;
  }
}

template <Scan S>
inline std::size_t scan(const char* p, std::size_t n, std::uint32_t* out,
                        std::size_t cap) {
  if constexpr (S == Scan::Scalar) {
    return scan_scalar(p, n, out, cap);
  } else if constexpr (S == Scan::Swar) {
    return scan_swar(p, n, out, cap);
#if defined(__ARM_NEON)
  } else if constexpr (S == Scan::Neon || S == Scan::Best) {
    return scan_neon(p, n, out, cap);
#endif
#if defined(__SSE2__)
  } else if constexpr (S == Scan::Sse2 || S == Scan::Best) {
    return scan_sse2(p, n, out, cap);
#endif
  } else {
    static_assert(S == Scan::Best, "scanner not available on this target");
    return scan_swar(p, n, out, cap);
  }
}

inline const char* scan_name(Scan s) {
  switch (s) {
    case Scan::Scalar: return "scalar";
    case Scan::Swar: return "swar";
    case Scan::Neon: return "neon";
    case Scan::Sse2: return "sse2";
    case Scan::Best: return "best";
  }
  return "?";
}

}  // namespace fixparse
