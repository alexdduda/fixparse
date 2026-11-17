# fixparse

A zero-copy, zero-allocation FIX protocol parser in C++20, with SIMD
delimiter scanning, O(1) stream framing, and a differential fuzzer.

FIX is the text protocol brokers and exchanges use for orders and executions:

```
8=FIX.4.4|9=148|35=D|49=CLIENT|56=EXCH|34=12|...|55=AAPL|54=1|38=100|44=187.25|10=093|
```

(`|` stands for the SOH byte, `0x01`.) Every field is `tag=value`, the message
declares its own length in tag 9, and ends with a mod-256 checksum in tag 10.

## Results

Apple M3, Apple clang 17, `-O3`. 200,000 generated messages (48.7 MB, average
243 bytes): 45% market-data refreshes, 30% execution reports, 22% new orders,
3% heartbeats. Each case validates BodyLength and CheckSum, then reads
Symbol, OrderQty and Price. Median of 15 runs.

| case | ns/msg | GB/s | heap allocs/msg | vs naive |
|---|---:|---:|---:|---:|
| naive (split, `std::string`, hash map) | 1419 | 0.17 | 20.1 | 1.0x |
| fixparse, scalar scan | 228 | 1.07 | 0 | 6.2x |
| fixparse, SWAR scan | 166 | 1.47 | 0 | 8.6x |
| fixparse, NEON scan | 157 | 1.55 | 0 | 9.1x |
| stream: frame + parse | 139 | 1.76 | 0 | 10.2x |
| frame only | 7.6 | 32.0 | 0 | 186x |

Run `make bench` to reproduce. Numbers vary by a few percent between runs.

### What each optimization was worth

Each row adds one change, measured on the NEON per-message case:

| step | ns/msg |
|---|---:|
| naive baseline | 1419 |
| zero-copy field table, scalar SOH scan | 281 |
| NEON SOH scan | 198 |
| constexpr table for raw-data length tags (was a `switch`) | 169 |
| branch-free SWAR tag parsing | 155 |

Two of these surprised me, which is why the benchmark prints a breakdown:

- **The vectorized scan was not the bottleneck.** Finding every SOH costs
  32 ns per message. Walking the ~35 fields afterwards cost 134 ns.
- **The `switch` was.** It checks whether a tag is a raw-data length field
  (see below). With 16 scattered case values, clang compiled it into an
  out-of-line function with a compare tree, so every field paid for a call and
  several hard-to-predict branches. A 1.3 KB constexpr lookup table cut 30% off
  field walking. I had guessed the digit loop was the problem and wrote the
  SWAR tag parser first. It helped, but only by about 9%.

## Design

**Zero copy.** A parsed `Message` stores `(tag, offset, length)` triples that
point into the caller's buffer. Values come back as `std::string_view`. The
`Message` is reused across messages, so steady-state parsing never touches the
heap. The tests replace global `operator new` to verify that.

**Structural indexing.** Like simdjson, parsing runs in two passes. The first
finds every delimiter with SIMD: NEON on ARM, SSE2 on x86, and a portable SWAR
fallback that processes 8 bytes per step in a normal register. NEON has no
`movemask`, so it uses the narrowing-shift trick to pack 16 comparisons into
a 64-bit nibble mask. The second pass walks fields between delimiters.

**Branch-free tag parsing.** Tags are 1 to 7 digits in practice. The fast path
loads 8 bytes, finds the first non-digit with exact per-byte range checks
(no false positives from borrow propagation), and converts the digits with
three multiply-shift steps instead of a loop. Anything unusual falls back to
the scalar parser, so error reporting is identical.

**O(1) framing.** On a TCP stream you must find where one message ends before
parsing it. Most parsers scan for `10=`. `frame()` reads BodyLength from the
header and jumps straight to the trailer, so its cost does not depend on the
size of the message body. That is why it runs at 32 GB/s.

**Raw data fields.** FIX data fields (RawData, XmlData, Signature, and the
Encoded* text fields) may legally contain SOH and `=`. Each is preceded by a
length field. fixparse reads these by length rather than by delimiter.
Parsers that split on SOH break on them.

**Fixed-point prices.** `to_decimal("187.25")` returns `{18725, 2}`. Prices
never pass through `double`, because 0.1 has no exact binary representation.

## Correctness

- **189 unit tests**, covering every error path, every prefix of a message
  through the framer, and raw data containing SOH, `=`, and fake `10=` fields.
- **Differential testing.** Every scanner must produce exactly the same
  output as the scalar reference, on random buffers at every alignment and
  tail length. The SWAR tag parser is checked against the scalar one on 500k
  random inputs.
- **Fuzzing under AddressSanitizer and UBSan.** The fuzz target checks
  properties, not just crashes: all scanners agree, `frame()` agrees with
  `parse()`, and every returned value lies inside the input buffer. It runs on
  libFuzzer in CI, and on a FIX-aware mutation driver locally, since Apple
  clang ships without libFuzzer. UBSan caught a real bug during development:
  the SWAR fast path passed zero to `ctz` on an all-digit input.
- **Both SIMD paths are tested on one machine.** On Apple Silicon,
  `make test-x86` builds for x86-64 and runs under Rosetta, which exercises
  the SSE2 path.

## Usage

Header only. Add `include/` to your include path.

```cpp
#include "fixparse/fixparse.hpp"

fixparse::Message<> msg;  // reuse this across messages
std::size_t len;
while (fixparse::frame(stream, len) == fixparse::Error::Ok) {
  if (msg.parse(stream.substr(0, len)) == fixparse::Error::Ok && msg.msg_type() == "D") {
    auto symbol = msg.get(55);                        // std::optional<std::string_view>
    auto price = fixparse::to_decimal(*msg.get(44));  // {mantissa, scale}
  }
  stream.remove_prefix(len);
}
```

`frame()` returns `Error::Incomplete` when it needs more bytes, so the same
loop works on a partially filled socket buffer.

## Build

```
make test      # unit tests, plus the same tests under ASan and UBSan
make test-x86  # Apple Silicon only: x86-64 build under Rosetta (SSE2 path)
make fuzz      # 2M iterations of the mutation fuzzer under ASan and UBSan
make bench
```

## Limitations and next steps

- Repeating groups are returned as flat, ordered fields. Grouping them needs
  a data dictionary that says which tags belong to each group.
- `get()` is a linear scan. That is fast for typical messages but could be
  replaced with a small perfect hash for very large market-data snapshots.
- Next benchmarks to add: QuickFIX as a real-world baseline, and per-message
  latency percentiles on x86 using `rdtsc`. Apple Silicon timers tick every
  ~42 ns, which is too coarse to time single messages.
