// Baseline: the parser most people write first. Splits on SOH, copies every
// tag and value into std::string, stores them in a hash map, and validates the
// checksum. It is a fair, correct-for-normal-messages baseline, not a straw man.
#pragma once

#include <charconv>
#include <string>
#include <string_view>
#include <unordered_map>

namespace naive {

struct Message {
  std::unordered_map<int, std::string> fields;

  bool parse(std::string_view s) {
    fields.clear();
    std::size_t start = 0;
    std::size_t ck_start = 0;
    while (start < s.size()) {
      const std::size_t end = s.find('\x01', start);
      if (end == std::string_view::npos) return false;
      const std::string token(s.substr(start, end - start));
      const std::size_t eq = token.find('=');
      if (eq == std::string::npos) return false;
      int tag = 0;
      if (std::from_chars(token.data(), token.data() + eq, tag).ec != std::errc()) return false;
      if (tag == 10) ck_start = start;
      fields.emplace(tag, token.substr(eq + 1));
      start = end + 1;
    }
    unsigned sum = 0;
    for (std::size_t i = 0; i < ck_start; ++i) sum += static_cast<unsigned char>(s[i]);
    const auto it = fields.find(10);
    return it != fields.end() && std::stoi(it->second) == static_cast<int>(sum & 0xFF);
  }

  const std::string* get(int tag) const {
    const auto it = fields.find(tag);
    return it == fields.end() ? nullptr : &it->second;
  }
};

}  // namespace naive
