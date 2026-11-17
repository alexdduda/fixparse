// Benchmarks. Every case does the same work: take a framed message, validate
// BodyLength and CheckSum, and read Symbol (55), OrderQty (38) and Price (44).
//
// The corpus is 200k generated messages in one contiguous buffer, mixing order
// entry, execution reports and market-data refreshes in realistic proportions.
// Each case runs kRuns times over the full corpus; we report the median and
// best run. Allocations are counted by replacing global operator new.
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <new>
#include <random>
#include <string>
#include <vector>

#include "../tools/build.hpp"
#include "fixparse/fixparse.hpp"
#include "naive.hpp"

using namespace fixparse;

static std::size_t g_allocs = 0;
void* operator new(std::size_t n) {
  ++g_allocs;
  if (void* p = std::malloc(n ? n : 1)) return p;
  throw std::bad_alloc();
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }

static volatile std::uint64_t g_sink;
constexpr int kRuns = 15;
constexpr std::size_t kMessages = 200000;

struct Corpus {
  std::string stream;                    // all messages back to back
  std::vector<std::string_view> msgs;    // views into `stream`
  std::size_t bytes() const { return stream.size(); }
};

static Corpus make_corpus() {
  std::mt19937 rng(42);
  const char* syms[] = {"AAPL", "MSFT", "NVDA", "ESZ6", "BRK.B", "SHOP.TO", "TSLA", "XIU.TO"};
  auto px = [&] { return std::to_string(10 + rng() % 900) + "." + std::to_string(10 + rng() % 90); };
  auto qty = [&] { return std::to_string(1 + rng() % 5000); };
  std::vector<std::string> parts;
  std::size_t seq = 1;
  for (std::size_t i = 0; i < kMessages; ++i) {
    const std::string hdr = "49=SQPT|56=XCHG|34=" + std::to_string(seq++) + "|52=20261116-14:30:00.123|";
    const std::string sym = syms[rng() % 8];
    const unsigned kind = rng() % 100;
    std::string body;
    if (kind < 45) {  // market data incremental refresh, 2-8 entries
      const int n = 2 + static_cast<int>(rng() % 7);
      body = "35=X|" + hdr + "262=" + std::to_string(i) + "|268=" + std::to_string(n) + "|";
      for (int e = 0; e < n; ++e)
        body += "279=" + std::to_string(rng() % 3) + "|269=" + std::to_string(rng() % 2) + "|55=" + sym +
                "|270=" + px() + "|271=" + qty() + "|";
      body += "38=0|44=" + px() + "|";
    } else if (kind < 75) {  // execution report
      body = "35=8|" + hdr + "37=" + std::to_string(i) + "|11=C" + std::to_string(i) + "|17=E" +
             std::to_string(i) + "|150=F|39=2|55=" + sym + "|54=" + std::to_string(1 + rng() % 2) +
             "|38=" + qty() + "|44=" + px() + "|32=" + qty() + "|31=" + px() + "|151=0|14=" + qty() +
             "|6=" + px() + "|60=20261116-14:30:00.123|";
    } else if (kind < 97) {  // new order single
      body = "35=D|" + hdr + "11=C" + std::to_string(i) + "|21=1|55=" + sym + "|54=" +
             std::to_string(1 + rng() % 2) + "|60=20261116-14:30:00.123|38=" + qty() +
             "|40=2|44=" + px() + "|59=0|";
    } else {  // heartbeat
      body = "35=0|" + hdr + "55=HB|38=0|44=0|";
    }
    parts.push_back(fixtools::build(body));
  }
  Corpus c;
  for (const auto& p : parts) c.stream += p;
  std::size_t off = 0;
  for (const auto& p : parts) {
    c.msgs.emplace_back(c.stream.data() + off, p.size());
    off += p.size();
  }
  return c;
}

struct Result {
  double median_ns, best_ns, allocs_per_msg;
};

template <class F>
static Result run(const Corpus& c, F&& body) {
  body();  // warm up caches and branch predictors
  std::vector<double> ns;
  std::size_t allocs = 0;
  for (int r = 0; r < kRuns; ++r) {
    const std::size_t a0 = g_allocs;
    const auto t0 = std::chrono::steady_clock::now();
    body();
    const auto t1 = std::chrono::steady_clock::now();
    allocs += g_allocs - a0;
    ns.push_back(std::chrono::duration<double, std::nano>(t1 - t0).count() / c.msgs.size());
  }
  std::sort(ns.begin(), ns.end());
  return {ns[ns.size() / 2], ns.front(), static_cast<double>(allocs) / (kRuns * c.msgs.size())};
}

static void print(const char* name, const Result& r, const Corpus& c, double baseline_ns) {
  const double avg_bytes = static_cast<double>(c.bytes()) / c.msgs.size();
  std::printf("%-28s %8.1f %8.1f %10.2f %9.1f %9.1fx\n", name, r.median_ns, r.best_ns,
              avg_bytes / r.median_ns, r.allocs_per_msg, baseline_ns / r.median_ns);
}

template <Scan S>
static Result bench_fixparse(const Corpus& c) {
  static Message<256, S> m;
  return run(c, [&] {
    std::uint64_t acc = 0;
    for (auto s : c.msgs) {
      if (m.parse(s) != Error::Ok) std::abort();
      acc += m.get(55)->size() + m.get(38)->size();
      acc += static_cast<std::uint64_t>(to_decimal(*m.get(44))->mantissa);
    }
    g_sink = acc;
  });
}

int main() {
  const Corpus c = make_corpus();
  std::printf("corpus: %zu messages, %.1f MB, avg %.0f bytes/msg\n", c.msgs.size(), c.bytes() / 1e6,
              static_cast<double>(c.bytes()) / c.msgs.size());
  std::printf("%-28s %8s %8s %10s %9s %10s\n", "case", "ns/msg", "best", "GB/s", "allocs", "vs naive");

  naive::Message nm;
  const Result rn = run(c, [&] {
    std::uint64_t acc = 0;
    for (auto s : c.msgs) {
      if (!nm.parse(s)) std::abort();
      acc += nm.get(55)->size() + nm.get(38)->size() + nm.get(44)->size();
    }
    g_sink = acc;
  });
  print("naive (split + hash map)", rn, c, rn.median_ns);

  print("fixparse scalar", bench_fixparse<Scan::Scalar>(c), c, rn.median_ns);
  print("fixparse swar", bench_fixparse<Scan::Swar>(c), c, rn.median_ns);
#if defined(__ARM_NEON)
  print("fixparse neon", bench_fixparse<Scan::Neon>(c), c, rn.median_ns);
#endif
#if defined(__SSE2__)
  print("fixparse sse2", bench_fixparse<Scan::Sse2>(c), c, rn.median_ns);
#endif

  // Full pipeline on the raw byte stream: frame, then parse.
  static Message<256, Scan::Best> m;
  const Result rs = run(c, [&] {
    std::string_view rest = c.stream;
    std::uint64_t acc = 0;
    std::size_t len = 0;
    while (!rest.empty()) {
      if (frame(rest, len) != Error::Ok || m.parse(rest.substr(0, len)) != Error::Ok) std::abort();
      acc += m.get(55)->size();
      rest.remove_prefix(len);
    }
    g_sink = acc;
  });
  print("stream: frame + parse", rs, c, rn.median_ns);

  // Framing alone, to show it skips the body.
  const Result rf = run(c, [&] {
    std::string_view rest = c.stream;
    std::size_t len = 0, n = 0;
    while (!rest.empty()) {
      if (frame(rest, len) != Error::Ok) std::abort();
      rest.remove_prefix(len);
      ++n;
    }
    g_sink = n;
  });
  print("frame only", rf, c, rn.median_ns);

  // Where the time goes: each row adds one stage on top of the previous one.
  std::printf("\nbreakdown (best scanner, ns/msg):\n");
  static std::uint32_t pos[512];
  const Result b1 = run(c, [&] {
    std::uint64_t acc = 0;
    for (auto s : c.msgs) acc += scan<Scan::Best>(s.data(), s.size(), pos, 512);
    g_sink = acc;
  });
  const Options none{.verify_checksum = false, .verify_body_length = false};
  const Result b2 = run(c, [&] {
    std::uint64_t acc = 0;
    for (auto s : c.msgs) acc += static_cast<std::uint64_t>(m.parse(s, none));
    g_sink = acc;
  });
  const Result b3 = run(c, [&] {
    std::uint64_t acc = 0;
    for (auto s : c.msgs) acc += static_cast<std::uint64_t>(m.parse(s));
    g_sink = acc;
  });
  std::printf("  1. SOH scan only               %6.1f\n", b1.median_ns);
  std::printf("  2. + tag parsing, field table  %6.1f\n", b2.median_ns);
  std::printf("  3. + body length, checksum     %6.1f\n", b3.median_ns);
  return 0;
}
