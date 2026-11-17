// Differential fuzz target, libFuzzer-compatible.
//
// Beyond "does not crash under ASan/UBSan", it checks properties that must
// hold for every input:
//   1. Every scanner variant produces the same parse (same error, same fields).
//   2. If parse succeeds, frame() agrees on the message length.
//   3. If frame() returns Ok, the length is within the buffer.
//   4. Every returned value lies inside the input buffer (zero-copy invariant).
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <string_view>

#include "fixparse/fixparse.hpp"

using namespace fixparse;

[[noreturn]] static void fail(const char* what) {
  std::fprintf(stderr, "property violated: %s\n", what);
  std::abort();
}

template <class A, class B>
static void same(const A& a, Error ea, const B& b, Error eb) {
  if (ea != eb) fail("scanners disagree on error");
  if (ea != Error::Ok) return;
  if (a.size() != b.size()) fail("scanners disagree on field count");
  for (std::size_t i = 0; i < a.size(); ++i)
    if (a[i].tag != b[i].tag || a[i].value != b[i].value) fail("scanners disagree on a field");
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::string_view in(reinterpret_cast<const char*>(data), size);

  static Message<128, Scan::Scalar> scalar;
  static Message<128, Scan::Swar> swar;
  static Message<128, Scan::Best> best;
  const Error es = scalar.parse(in), ew = swar.parse(in), eb = best.parse(in);
  same(scalar, es, swar, ew);
  same(scalar, es, best, eb);

  if (es == Error::Ok) {
    for (std::size_t i = 0; i < scalar.size(); ++i) {
      const auto v = scalar[i].value;
      if (v.data() < in.data() || v.data() + v.size() > in.data() + in.size())
        fail("value outside input buffer");
    }
    std::size_t len = 0;
    if (frame(in, len) != Error::Ok || len != in.size()) fail("parse ok but frame disagrees");
  }

  // Random mutations almost always break the checksum, which would stop the
  // parse early. Re-run with validation off so the field walker is exercised.
  const Options lax{.verify_checksum = false, .verify_body_length = false};
  same(scalar, scalar.parse(in, lax), best, best.parse(in, lax));
  same(scalar, scalar.parse(in, lax), swar, swar.parse(in, lax));

  std::size_t len = 0;
  if (frame(in, len) == Error::Ok && len > in.size()) fail("frame length past buffer");

  for (const auto& m : {scalar.get(44), scalar.get(38)})
    if (m) { (void)to_decimal(*m); (void)to_int(*m); }
  return 0;
}
