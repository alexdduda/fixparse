// Zero-copy FIX message parsing.
//
// `Message` never copies or allocates. Fields are stored as (tag, offset,
// length) triples that point back into the caller's buffer, so the buffer must
// outlive any string_view handed out. A Message is meant to be reused: parse
// into the same object for every message on a session.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

#include "fixparse/scan.hpp"

namespace fixparse {

enum class Error : std::uint8_t {
  Ok,
  Incomplete,         // framer: need more bytes
  BadBeginString,     // first field is not 8=
  BadBodyLength,      // second field is not 9=<digits>, or the length is wrong
  BadMsgType,         // third field is not 35=
  BadChecksumField,   // last field is not 10=<3 digits><SOH>
  ChecksumMismatch,
  BadTag,             // empty, non-numeric, leading zero, or overflowing tag
  MissingEquals,
  EmptyValue,
  BadDataLength,      // raw data field does not match its length field
  TrailingBytes,      // bytes after the checksum field
  TooManyFields,
};

inline const char* error_name(Error e) {
  switch (e) {
    case Error::Ok: return "Ok";
    case Error::Incomplete: return "Incomplete";
    case Error::BadBeginString: return "BadBeginString";
    case Error::BadBodyLength: return "BadBodyLength";
    case Error::BadMsgType: return "BadMsgType";
    case Error::BadChecksumField: return "BadChecksumField";
    case Error::ChecksumMismatch: return "ChecksumMismatch";
    case Error::BadTag: return "BadTag";
    case Error::MissingEquals: return "MissingEquals";
    case Error::EmptyValue: return "EmptyValue";
    case Error::BadDataLength: return "BadDataLength";
    case Error::TrailingBytes: return "TrailingBytes";
    case Error::TooManyFields: return "TooManyFields";
  }
  return "?";
}

struct Options {
  bool verify_checksum = true;
  bool verify_body_length = true;
};

struct Field {
  std::uint32_t tag;
  std::string_view value;
};

namespace detail {

// FIX "data" fields carry raw bytes that may legally contain SOH and '='.
// Each one is preceded by a length field; most parsers ignore this and split
// these messages in the wrong place.
inline constexpr std::uint32_t data_tag_for_length(std::uint32_t len_tag) {
  switch (len_tag) {
    case 90: return 91;    // SecureDataLen -> SecureData
    case 93: return 89;    // SignatureLength -> Signature
    case 95: return 96;    // RawDataLength -> RawData
    case 212: return 213;  // XmlDataLen -> XmlData
    case 348: return 349;  // EncodedIssuerLen
    case 350: return 351;  // EncodedSecurityDescLen
    case 352: return 353;  // EncodedListExecInstLen
    case 354: return 355;  // EncodedTextLen
    case 356: return 357;  // EncodedSubjectLen
    case 358: return 359;  // EncodedHeadlineLen
    case 360: return 361;  // EncodedAllocTextLen
    case 362: return 363;  // EncodedUnderlyingIssuerLen
    case 364: return 365;  // EncodedUnderlyingSecurityDescLen
    case 445: return 446;  // EncodedListStatusTextLen
    case 618: return 619;  // EncodedLegIssuerLen
    case 621: return 622;  // EncodedLegSecurityDescLen
    default: return 0;
  }
}

// The switch above compiles to an out-of-line compare tree that costs a call
// and several unpredictable branches on every field. This constexpr table makes
// the per-field check a single bounds test and load. The table is 1.3 KB.
inline constexpr std::uint32_t kDataTagLimit = 640;
struct DataTagTable {
  std::uint16_t t[kDataTagLimit];
  constexpr DataTagTable() : t{} {
    for (std::uint32_t i = 0; i < kDataTagLimit; ++i)
      t[i] = static_cast<std::uint16_t>(data_tag_for_length(i));
  }
};
inline constexpr DataTagTable kDataTags{};

inline std::uint32_t data_tag_lookup(std::uint32_t tag) {
  return tag < kDataTagLimit ? kDataTags.t[tag] : 0;
}

// Parses an unsigned decimal of at most 9 digits (fits in uint32 without
// overflow checks per digit). Returns false on empty, non-digit, or too long.
inline bool parse_u32(const char* p, std::size_t n, std::uint32_t& out) {
  if (n == 0 || n > 9) return false;
  std::uint32_t v = 0;
  for (std::size_t i = 0; i < n; ++i) {
    const unsigned d = static_cast<unsigned char>(p[i]) - '0';
    if (d > 9) return false;
    v = v * 10 + d;
  }
  out = v;
  return true;
}

// Parses the tag in [p, end) up to the first '='. On success sets `tag` and
// returns a pointer to the first value byte.
inline const char* parse_tag(const char* p, const char* end, std::uint32_t& tag,
                             Error& err) {
  const char* q = p;
  std::uint32_t v = 0;
  while (q < end) {
    const unsigned d = static_cast<unsigned char>(*q) - '0';
    if (d > 9) break;
    if (q - p == 9) { err = Error::BadTag; return nullptr; }
    v = v * 10 + d;
    ++q;
  }
  if (q == end) { err = Error::MissingEquals; return nullptr; }
  if (*q != '=' || q == p || *p == '0') { err = Error::BadTag; return nullptr; }
  tag = v;
  return q + 1;
}

// Branch-free fast path for the common case: a 1 to 7 digit tag followed by
// '=' within the next 8 bytes. Loads 8 bytes once, finds the first non-digit
// with exact per-byte range checks, and converts the digits with three
// multiply-shift steps instead of a loop. Returns nullptr when the fast path
// does not apply; the caller then falls back to parse_tag, so error reporting
// stays identical. Requires 8 readable bytes at p.
inline const char* parse_tag_swar(const char* p, std::uint32_t& tag) {
  constexpr std::uint64_t kHi = 0x8080808080808080ULL;
  constexpr std::uint64_t kLow7 = 0x7F7F7F7F7F7F7F7FULL;
  std::uint64_t w;
  std::memcpy(&w, p, 8);
  const std::uint64_t low = w & kLow7;
  const std::uint64_t above_9 = low + 0x4646464646464646ULL;    // high bit if > '9'
  const std::uint64_t at_least_0 = low + 0x5050505050505050ULL; // high bit if >= '0'
  const std::uint64_t digit = ~above_9 & at_least_0 & ~w & kHi;
  const std::uint64_t non_digit = ~digit & kHi;
  if (non_digit == 0) return nullptr;  // 8 digits, no '=' yet: let the slow path decide
  const unsigned f = static_cast<unsigned>(__builtin_ctzll(non_digit)) >> 3;  // tag length
  if (f == 0 || f > 7 || p[f] != '=' || p[0] == '0') return nullptr;
  // Right-align the f digits in the high bytes (zero bytes become leading
  // zeros), then combine pairs, quads, and octets.
  std::uint64_t v = w << (8 * (8 - f));  // the & 0x0F below strips the '0' bias
  v = ((v & 0x0F0F0F0F0F0F0F0FULL) * 2561) >> 8;
  v = ((v & 0x00FF00FF00FF00FFULL) * 6553601) >> 16;
  v = ((v & 0x0000FFFF0000FFFFULL) * 42949672960001ULL) >> 32;
  tag = static_cast<std::uint32_t>(v);
  return p + f + 1;
}

inline std::uint32_t checksum(const char* p, std::size_t n) {
  // A plain loop: clang and gcc both vectorize this at -O2/-O3.
  std::uint32_t s = 0;
  for (std::size_t i = 0; i < n; ++i) s += static_cast<unsigned char>(p[i]);
  return s & 0xFF;
}

}  // namespace detail

template <std::size_t MaxFields = 256, Scan S = Scan::Best>
class Message {
 public:
  Error parse(std::string_view buf, const Options& opt = {}) {
    nfields_ = 0;
    buf_ = buf.data();
    const char* const p = buf.data();
    const std::size_t n = buf.size();
    if (n > UINT32_MAX) return Error::TooManyFields;
    if (n < 2 || p[0] != '8' || p[1] != '=') return Error::BadBeginString;

    const std::size_t nsoh = scan<S>(p, n, soh_, kSohCap);
    if (nsoh == kOverflow) return Error::TooManyFields;
    if (nsoh == 0) return Error::BadChecksumField;
    if (soh_[nsoh - 1] != n - 1) return Error::TrailingBytes;

    std::size_t si = 0;          // next SOH index
    std::uint32_t cursor = 0;    // start of the next field
    std::uint32_t want_data_tag = 0, data_len = 0;

    while (cursor < n) {
      if (nfields_ == MaxFields) return Error::TooManyFields;
      Error err = Error::Ok;
      std::uint32_t tag;
      const char* field = p + cursor;

      if (want_data_tag) {
        const char* v = detail::parse_tag(field, p + n, tag, err);
        if (!v) return err;
        if (tag != want_data_tag) return Error::BadDataLength;
        const auto vo = static_cast<std::size_t>(v - p);
        if (vo + data_len >= n || p[vo + data_len] != kSOH) return Error::BadDataLength;
        const auto end = static_cast<std::uint32_t>(vo + data_len);
        while (si < nsoh && soh_[si] < end) ++si;  // skip SOHs inside the data
        ++si;                                      // the terminating SOH
        fields_[nfields_++] = {tag, static_cast<std::uint32_t>(vo), data_len};
        cursor = end + 1;
        want_data_tag = 0;
        continue;
      }

      const std::uint32_t end = soh_[si++];
#ifndef FIXPARSE_NO_SWAR_TAG
      const char* v = (cursor + 8 <= n) ? detail::parse_tag_swar(field, tag) : nullptr;
#else
      const char* v = nullptr;  // ablation: scalar tag parsing only
#endif
      if (!v) v = detail::parse_tag(field, p + end, tag, err);
      if (!v) return err;
      const auto vo = static_cast<std::uint32_t>(v - p);
      if (vo == end) return Error::EmptyValue;
      fields_[nfields_++] = {tag, vo, end - vo};
      cursor = end + 1;

      if (const std::uint32_t dt = detail::data_tag_lookup(tag)) [[unlikely]] {
        if (!detail::parse_u32(p + vo, end - vo, data_len)) return Error::BadDataLength;
        want_data_tag = dt;
      }
    }
    if (want_data_tag) return Error::BadDataLength;
    return validate(opt);
  }

  std::size_t size() const { return nfields_; }
  Field operator[](std::size_t i) const {
    const Ref& r = fields_[i];
    return {r.tag, {buf_ + r.off, r.len}};
  }

  // First occurrence of `tag`. A linear scan beats hashing at typical FIX
  // message sizes (10 to 40 fields); see bench/ for the measurement.
  std::optional<std::string_view> get(std::uint32_t tag) const {
    for (std::size_t i = 0; i < nfields_; ++i)
      if (fields_[i].tag == tag) return std::string_view(buf_ + fields_[i].off, fields_[i].len);
    return std::nullopt;
  }

  std::string_view msg_type() const { return (*this)[2].value; }

 private:
  struct Ref {
    std::uint32_t tag, off, len;
  };
  // Raw data fields can contain extra SOHs, so give the index some headroom.
  static constexpr std::size_t kSohCap = MaxFields * 2;

  Error validate(const Options& opt) const {
    if (nfields_ < 4) return Error::BadChecksumField;
    if (fields_[0].tag != 8) return Error::BadBeginString;
    if (fields_[1].tag != 9) return Error::BadBodyLength;
    if (fields_[2].tag != 35) return Error::BadMsgType;
    const Ref& ck = fields_[nfields_ - 1];
    if (ck.tag != 10 || ck.len != 3) return Error::BadChecksumField;
    std::uint32_t ck_val;
    if (!detail::parse_u32(buf_ + ck.off, 3, ck_val)) return Error::BadChecksumField;
    for (std::size_t i = 3; i + 1 < nfields_; ++i)
      if (fields_[i].tag == 10) return Error::BadChecksumField;

    const std::uint32_t ck_start = ck.off - 3;  // start of "10="
    if (opt.verify_body_length) {
      const Ref& bl = fields_[1];
      std::uint32_t body_len;
      if (!detail::parse_u32(buf_ + bl.off, bl.len, body_len)) return Error::BadBodyLength;
      const std::uint32_t body_start = bl.off + bl.len + 1;
      if (ck_start - body_start != body_len) return Error::BadBodyLength;
    }
    if (opt.verify_checksum && detail::checksum(buf_, ck_start) != ck_val)
      return Error::ChecksumMismatch;
    return Error::Ok;
  }

  const char* buf_ = nullptr;
  std::size_t nfields_ = 0;
  Ref fields_[MaxFields];
  std::uint32_t soh_[kSohCap];
};

// Finds the length of the first complete message at the front of a TCP byte
// stream. Uses BodyLength to jump straight to the checksum, so it reads only
// the header and the trailer, never the body. Returns Ok and sets `len`, or
// Incomplete if more bytes are needed, or an error if the header is garbled.
inline Error frame(std::string_view buf, std::size_t& len) {
  const char* p = buf.data();
  const std::size_t n = buf.size();
  // "8=" ... SOH "9=" digits SOH
  if (n >= 1 && p[0] != '8') return Error::BadBeginString;
  if (n >= 2 && p[1] != '=') return Error::BadBeginString;
  std::size_t i = 2;
  while (i < n && p[i] != kSOH) {
    if (i > 32) return Error::BadBeginString;
    ++i;
  }
  if (i >= n) return Error::Incomplete;
  if (i == 2) return Error::BadBeginString;
  ++i;  // past SOH
  if (n < i + 2) return Error::Incomplete;
  if (p[i] != '9' || p[i + 1] != '=') return Error::BadBodyLength;
  i += 2;
  const std::size_t digits = i;
  while (i < n && p[i] != kSOH) {
    if (i - digits >= 9) return Error::BadBodyLength;
    ++i;
  }
  if (i >= n) return Error::Incomplete;
  std::uint32_t body_len;
  if (!detail::parse_u32(p + digits, i - digits, body_len)) return Error::BadBodyLength;
  const std::size_t total = i + 1 + body_len + 7;  // + "10=NNN" SOH
  if (n < total) return Error::Incomplete;
  const char* t = p + total - 7;
  if (t[0] != '1' || t[1] != '0' || t[2] != '=' || t[6] != kSOH)
    return Error::BadChecksumField;
  len = total;
  return Error::Ok;
}

}  // namespace fixparse
