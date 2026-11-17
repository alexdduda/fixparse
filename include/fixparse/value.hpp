// Allocation-free decoding of FIX field values.
//
// Prices are decoded as fixed-point decimals, never as double: 0.1 has no exact
// binary representation, and a trading system that rounds prices through
// floating point eventually sends an order at the wrong price.
#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

namespace fixparse {

inline std::optional<std::uint64_t> to_uint(std::string_view s) {
  if (s.empty() || s.size() > 19) return std::nullopt;  // 19 digits always fit
  std::uint64_t v = 0;
  for (char c : s) {
    const unsigned d = static_cast<unsigned char>(c) - '0';
    if (d > 9) return std::nullopt;
    v = v * 10 + d;
  }
  return v;
}

inline std::optional<std::int64_t> to_int(std::string_view s) {
  const bool neg = !s.empty() && s[0] == '-';
  if (neg) s.remove_prefix(1);
  const auto u = to_uint(s);
  if (!u || *u > static_cast<std::uint64_t>(INT64_MAX)) return std::nullopt;
  return neg ? -static_cast<std::int64_t>(*u) : static_cast<std::int64_t>(*u);
}

// value == mantissa * 10^-scale, e.g. "-12.340" -> {-12340, 3}.
struct Decimal {
  std::int64_t mantissa;
  std::uint8_t scale;
  friend bool operator==(const Decimal&, const Decimal&) = default;
};

// Accepts FIX Price/Qty/Amt syntax: optional '-', digits, optional '.' and
// digits. At least one digit overall. No exponents, no '+', no whitespace.
inline std::optional<Decimal> to_decimal(std::string_view s) {
  std::size_t i = 0;
  const bool neg = !s.empty() && s[0] == '-';
  if (neg) i = 1;
  std::uint64_t m = 0;
  std::uint8_t scale = 0;
  bool seen_dot = false, seen_digit = false;
  for (; i < s.size(); ++i) {
    const char c = s[i];
    if (c == '.') {
      if (seen_dot) return std::nullopt;
      seen_dot = true;
      continue;
    }
    const unsigned d = static_cast<unsigned char>(c) - '0';
    if (d > 9) return std::nullopt;
    if (m > (static_cast<std::uint64_t>(INT64_MAX) - d) / 10) return std::nullopt;
    m = m * 10 + d;
    seen_digit = true;
    if (seen_dot) {
      if (scale == 18) return std::nullopt;
      ++scale;
    }
  }
  if (!seen_digit) return std::nullopt;
  const auto sm = static_cast<std::int64_t>(m);
  return Decimal{neg ? -sm : sm, scale};
}

}  // namespace fixparse
