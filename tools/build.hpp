// Test and benchmark helper: builds a valid FIX message with correct
// BodyLength and CheckSum. Uses '|' as a readable stand-in for SOH.
#pragma once

#include <cstdio>
#include <string>
#include <string_view>

namespace fixtools {

inline std::string soh(std::string_view s) {
  std::string out(s);
  for (char& c : out)
    if (c == '|') c = '\x01';
  return out;
}

inline std::string pipes(std::string_view s) {
  std::string out(s);
  for (char& c : out)
    if (c == '\x01') c = '|';
  return out;
}

// `body` is everything after 9=..| and before 10=, starting with 35=, written
// with '|' separators and ending in '|'. Raw bytes (including real SOH) may be
// spliced in by the caller and are preserved.
inline std::string build(std::string_view body_pipes, std::string_view begin = "FIX.4.4") {
  const std::string body = soh(body_pipes);
  std::string m = "8=" + std::string(begin) + "\x01" + "9=" + std::to_string(body.size()) + "\x01" + body;
  unsigned sum = 0;
  for (unsigned char c : m) sum += c;
  char ck[8];
  std::snprintf(ck, sizeof ck, "10=%03u\x01", sum & 0xFF);
  return m + ck;
}

// Same, but the body is used byte for byte (no '|' translation), so it can
// carry '|' or SOH inside raw data fields.
inline std::string build_raw(std::string_view body, std::string_view begin = "FIX.4.4") {
  std::string m = "8=" + std::string(begin) + "\x01" + "9=" + std::to_string(body.size()) + "\x01" + std::string(body);
  unsigned sum = 0;
  for (unsigned char c : m) sum += c;
  char ck[8];
  std::snprintf(ck, sizeof ck, "10=%03u\x01", sum & 0xFF);
  return m + ck;
}

}  // namespace fixtools
