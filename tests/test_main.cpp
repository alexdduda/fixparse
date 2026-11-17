// Unit tests. No framework dependency: a failed CHECK prints and counts.
#include <cstdio>
#include <cstdlib>
#include <new>
#include <random>
#include <string>
#include <vector>

#include "../tools/build.hpp"
#include "fixparse/fixparse.hpp"

using namespace fixparse;
using fixtools::build;
using fixtools::build_raw;
using fixtools::soh;

// ---- allocation counter: proves the hot path never touches the heap ----
static std::size_t g_allocs = 0;
void* operator new(std::size_t n) {
  ++g_allocs;
  if (void* p = std::malloc(n ? n : 1)) return p;
  throw std::bad_alloc();
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }

static int g_fail = 0, g_pass = 0;
#define CHECK(cond)                                                     \
  do {                                                                  \
    if (cond) ++g_pass;                                                 \
    else { ++g_fail; std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); } \
  } while (0)
#define CHECK_ERR(got, want)                                            \
  do {                                                                  \
    Error g_ = (got), w_ = (want);                                      \
    if (g_ == w_) ++g_pass;                                             \
    else { ++g_fail; std::printf("FAIL %s:%d: got %s want %s\n", __FILE__, __LINE__, \
                                 error_name(g_), error_name(w_)); }      \
  } while (0)

static const std::string kOrder = build(
    "35=D|49=CLIENT|56=EXCH|34=12|52=20261116-14:30:00.123|11=ORD123|55=AAPL|54=1|"
    "38=100|40=2|44=187.25|59=0|60=20261116-14:30:00.123|");

// Parses with every available scanner and checks they agree.
static Error parse_all(std::string_view s, Options opt = {}) {
  static Message<64, Scan::Scalar> a;
  static Message<64, Scan::Swar> b;
  static Message<64, Scan::Best> c;
  const Error ea = a.parse(s, opt), eb = b.parse(s, opt), ec = c.parse(s, opt);
  CHECK(ea == eb);
  CHECK(ea == ec);
  if (ea == Error::Ok && eb == Error::Ok && ec == Error::Ok) {
    CHECK(a.size() == b.size() && a.size() == c.size());
    for (std::size_t i = 0; i < a.size() && i < b.size() && i < c.size(); ++i) {
      CHECK(a[i].tag == b[i].tag && a[i].tag == c[i].tag);
      CHECK(a[i].value == b[i].value && a[i].value == c[i].value);
    }
  }
  return ea;
}

static void test_valid() {
  Message<> m;
  CHECK_ERR(m.parse(kOrder), Error::Ok);
  CHECK(m.size() == 16);
  CHECK(m.msg_type() == "D");
  CHECK(m.get(55) == "AAPL");
  CHECK(m.get(44) == "187.25");
  CHECK(!m.get(9999));
  CHECK(m[0].tag == 8 && m[0].value == "FIX.4.4");
  CHECK(m[m.size() - 1].tag == 10);
  // values point into the caller's buffer: zero copy
  CHECK(m.get(55)->data() >= kOrder.data() && m.get(55)->data() < kOrder.data() + kOrder.size());
  CHECK_ERR(parse_all(kOrder), Error::Ok);
}

static void test_values_with_equals() {
  const std::string s = build("35=D|58=a=b==c|");
  Message<> m;
  CHECK_ERR(m.parse(s), Error::Ok);
  CHECK(m.get(58) == "a=b==c");
}

static void test_errors() {
  std::string s = kOrder;
  s[s.size() - 2] = s[s.size() - 2] == '0' ? '1' : '0';  // corrupt checksum digit
  CHECK_ERR(parse_all(s), Error::ChecksumMismatch);
  CHECK_ERR(parse_all(s, {.verify_checksum = false}), Error::Ok);

  CHECK_ERR(parse_all(soh("9=5|8=FIX.4.4|35=D|10=000|")), Error::BadBeginString);
  CHECK_ERR(parse_all(""), Error::BadBeginString);

  // body length off by one
  std::string bl = kOrder;
  const auto pos = bl.find("9=") + 2;
  bl[pos + 1] = static_cast<char>(bl[pos + 1] + 1);
  CHECK_ERR(parse_all(bl, {.verify_checksum = false}), Error::BadBodyLength);

  CHECK_ERR(parse_all(build("49=X|35=D|")), Error::BadMsgType);
  CHECK_ERR(parse_all(build("35=D|abc=1|")), Error::BadTag);
  CHECK_ERR(parse_all(build("35=D|058=1|")), Error::BadTag);   // leading zero
  CHECK_ERR(parse_all(build("35=D|=1|")), Error::BadTag);      // empty tag
  CHECK_ERR(parse_all(build("35=D|1234567890=1|")), Error::BadTag);
  CHECK_ERR(parse_all(build("35=D|58|")), Error::MissingEquals);
  CHECK_ERR(parse_all(build("35=D|58=|")), Error::EmptyValue);
  CHECK_ERR(parse_all(build("35=D|10=000|")), Error::BadChecksumField);  // 10 not last
  CHECK_ERR(parse_all(kOrder + "x"), Error::TrailingBytes);
  CHECK_ERR(parse_all(soh("8=FIX.4.4|9=5|35=D|10=12|")), Error::BadChecksumField);

  std::string many = "35=D|";
  for (int i = 0; i < 100; ++i) many += "58=x|";
  CHECK_ERR(parse_all(build(many)), Error::TooManyFields);  // cap is 64 in parse_all
}

static void test_raw_data() {
  // RawData (96) legally contains SOH, '=', and digits that look like tags.
  const std::string data = std::string("ab\x01" "10=123\x01" "c=d", 12);
  const std::string body = soh("35=D|95=") + std::to_string(data.size()) + "\x01" + "96=" + data +
                           "\x01" + soh("55=MSFT|");
  const std::string s = build_raw(body);
  Message<> m;
  CHECK_ERR(m.parse(s), Error::Ok);
  CHECK(m.get(96) == data);
  CHECK(m.get(55) == "MSFT");
  CHECK_ERR(parse_all(s), Error::Ok);

  // length says 5 but data is longer
  const std::string bad = build_raw(soh("35=D|95=5|96=") + data + "\x01");
  CHECK_ERR(parse_all(bad), Error::BadDataLength);
  // length field not followed by its data field
  CHECK_ERR(parse_all(build("35=D|95=3|55=abc|")), Error::BadDataLength);
  CHECK_ERR(parse_all(build("35=D|95=x|96=abc|")), Error::BadDataLength);
}

static void test_frame() {
  std::size_t len = 0;
  CHECK_ERR(frame(kOrder, len), Error::Ok);
  CHECK(len == kOrder.size());

  // every strict prefix is Incomplete, never an error and never Ok
  bool all_incomplete = true;
  for (std::size_t i = 0; i < kOrder.size(); ++i)
    if (frame(std::string_view(kOrder).substr(0, i), len) != Error::Incomplete) all_incomplete = false;
  CHECK(all_incomplete);

  // two back-to-back messages split correctly
  const std::string two = kOrder + build("35=0|");
  CHECK_ERR(frame(two, len), Error::Ok);
  CHECK(len == kOrder.size());
  CHECK_ERR(frame(std::string_view(two).substr(len), len), Error::Ok);

  CHECK_ERR(frame("GARBAGE", len), Error::BadBeginString);
  CHECK_ERR(frame(soh("8=FIX.4.4|35=D|"), len), Error::BadBodyLength);
  CHECK_ERR(frame(soh("8=FIX.4.4|9=3|35=D|XX=123|"), len), Error::BadChecksumField);
}

static void test_values() {
  CHECK(to_uint("0") == 0u);
  CHECK(to_uint("18446744073709551615") == std::nullopt);  // 20 digits rejected
  CHECK(to_uint("12a") == std::nullopt);
  CHECK(to_int("-42") == -42);
  CHECK(to_int("-") == std::nullopt);
  CHECK((to_decimal("187.25") == Decimal{18725, 2}));
  CHECK((to_decimal("-0.5") == Decimal{-5, 1}));
  CHECK((to_decimal("100") == Decimal{100, 0}));
  CHECK((to_decimal(".5") == Decimal{5, 1}));
  CHECK((to_decimal("5.") == Decimal{5, 0}));
  CHECK(to_decimal("1e5") == std::nullopt);
  CHECK(to_decimal("1.2.3") == std::nullopt);
  CHECK(to_decimal(".") == std::nullopt);
  CHECK(to_decimal("") == std::nullopt);
  CHECK(to_decimal("99999999999999999999") == std::nullopt);
}

// Random buffers with a high density of SOH bytes: every scanner must agree
// with the scalar reference, including at every alignment and tail length.
static void test_scanners_agree() {
  std::mt19937 rng(12345);
  std::vector<char> buf(300);
  std::uint32_t a[300], b[300], c[300];
  bool ok = true;
  for (int iter = 0; iter < 20000; ++iter) {
    const std::size_t n = rng() % buf.size();
    const unsigned density = 1 + rng() % 8;
    for (std::size_t i = 0; i < n; ++i)
      buf[i] = (rng() % density == 0) ? '\x01' : static_cast<char>(rng() & 0xFF);
    const std::size_t cap = 1 + rng() % 300;
    const auto ka = scan<Scan::Scalar>(buf.data(), n, a, cap);
    const auto kb = scan<Scan::Swar>(buf.data(), n, b, cap);
    const auto kc = scan<Scan::Best>(buf.data(), n, c, cap);
    if (ka != kb || ka != kc) { ok = false; break; }
    if (ka != kOverflow)
      for (std::size_t i = 0; i < ka; ++i)
        if (a[i] != b[i] || a[i] != c[i]) ok = false;
  }
  CHECK(ok);
}

// Whenever the SWAR tag fast path accepts an input, it must agree exactly with
// the scalar parser. Inputs are biased toward digits and '=' to hit edge cases.
static void test_tag_fast_path() {
  std::mt19937 rng(7);
  const char alphabet[] = "0123456789=\x01" "a/:";
  char buf[16];
  bool ok = true;
  int accepted = 0;
  for (int iter = 0; iter < 500000; ++iter) {
    for (char& ch : buf) ch = alphabet[rng() % (sizeof alphabet - 1)];
    if (rng() % 2) buf[1 + rng() % 7] = '=';
    std::uint32_t t1 = 0, t2 = 0;
    Error e = Error::Ok;
    const char* fast = detail::parse_tag_swar(buf, t1);
    const char* slow = detail::parse_tag(buf, buf + sizeof buf, t2, e);
    if (fast) {
      ++accepted;
      if (fast != slow || t1 != t2) ok = false;
    }
  }
  CHECK(ok);
  CHECK(accepted > 10000);
  std::uint32_t t = 0;
  CHECK(detail::parse_tag_swar("1234567=xxxxxxx", t) && t == 1234567);
  CHECK(detail::parse_tag_swar("8=FIX.4.4", t) && t == 8);
  CHECK(!detail::parse_tag_swar("12345678=xxxxxx", t));  // too long for the fast path
}

static void test_zero_alloc() {
  Message<> m;
  std::size_t len;
  const std::size_t before = g_allocs;
  for (int i = 0; i < 1000; ++i) {
    (void)frame(kOrder, len);
    (void)m.parse(kOrder);
    (void)to_decimal(*m.get(44));
  }
  CHECK(g_allocs == before);
}

int main() {
  test_valid();
  test_values_with_equals();
  test_errors();
  test_raw_data();
  test_frame();
  test_values();
  test_scanners_agree();
  test_tag_fast_path();
  test_zero_alloc();
  std::printf("%d passed, %d failed (best scanner: %s)\n", g_pass, g_fail,
#if defined(__ARM_NEON)
              "neon"
#elif defined(__SSE2__)
              "sse2"
#else
              "swar"
#endif
  );
  return g_fail ? 1 : 0;
}
