// Minimal mutation fuzzer for platforms without libFuzzer (Apple clang).
// Starts from valid FIX messages and applies FIX-aware mutations, so most
// inputs get deep into the parser instead of failing on the first byte.
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <random>
#include <string>
#include <vector>

#include "../tools/build.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size);

int main(int argc, char** argv) {
  const long iters = argc > 1 ? std::atol(argv[1]) : 1000000;
  const unsigned seed = argc > 2 ? static_cast<unsigned>(std::atol(argv[2])) : 1;
  std::mt19937_64 rng(seed);

  const std::string raw = std::string("x\x01" "10=1\x01" "=", 7);
  const std::vector<std::string> corpus = {
      fixtools::build("35=D|49=A|56=B|34=1|52=20261116-14:30:00.123|11=X|55=AAPL|54=1|38=100|40=2|44=187.25|"),
      fixtools::build("35=8|37=1|17=2|150=F|39=2|55=MSFT|54=2|38=50|32=50|31=401.10|151=0|14=50|6=401.10|"),
      fixtools::build("35=X|268=2|279=0|269=0|55=ES|270=5012.25|271=10|279=1|269=1|55=ES|270=5012.50|271=3|"),
      fixtools::build("35=0|"),
      fixtools::build_raw(fixtools::soh("35=D|95=7|96=") + raw + "\x01"),
  };
  const char tokens[] = {'\x01', '=', '|', '0', '1', '9', '8', '-', '.'};

  for (long it = 0; it < iters; ++it) {
    std::string s = corpus[rng() % corpus.size()];
    if (rng() % 4 == 0) s += corpus[rng() % corpus.size()];  // stream of two
    const int nmut = 1 + static_cast<int>(rng() % 4);
    for (int k = 0; k < nmut && !s.empty(); ++k) {
      const std::size_t i = rng() % s.size();
      switch (rng() % 6) {
        case 0: s[i] = static_cast<char>(rng()); break;                       // random byte
        case 1: s[i] = tokens[rng() % sizeof tokens]; break;                  // structural byte
        case 2: s.erase(i, 1 + rng() % 4); break;                             // delete
        case 3: s.insert(i, 1, tokens[rng() % sizeof tokens]); break;         // insert
        case 4: s.resize(i); break;                                           // truncate
        case 5: s.insert(i, s.substr(rng() % s.size(), rng() % 16)); break;  // duplicate chunk
      }
    }
    LLVMFuzzerTestOneInput(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
    // Also feed the unmutated corpus with every truncation point occasionally.
    if (it % 100000 == 0)
      for (const auto& c : corpus)
        for (std::size_t n = 0; n <= c.size(); ++n)
          LLVMFuzzerTestOneInput(reinterpret_cast<const std::uint8_t*>(c.data()), n);
  }
  std::printf("fuzz: %ld iterations, no property violations\n", iters);
  return 0;
}
